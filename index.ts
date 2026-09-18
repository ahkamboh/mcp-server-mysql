#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ListToolsRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { log } from "./src/utils/index.js";
import type { TableRow, ColumnRow } from "./src/types/index.js";
import {
  ALLOW_DELETE_OPERATION,
  ALLOW_DDL_OPERATION,
  ALLOW_INSERT_OPERATION,
  ALLOW_UPDATE_OPERATION,
  SCHEMA_DELETE_PERMISSIONS,
  SCHEMA_DDL_PERMISSIONS,
  SCHEMA_INSERT_PERMISSIONS,
  SCHEMA_UPDATE_PERMISSIONS,
  isMultiDbMode,
  mcpConfig as config,
  MCP_VERSION as version,
  IS_REMOTE_MCP,
  PORT,
  DEFAULT_BRAND,
  STARTUP_BRAND,
  type Brand,
} from "./src/config/index.js";
import {
  safeExit,
  getPool,
  executeQuery,
  executeReadOnlyQuery,
  closeAllPools,
} from "./src/db/index.js";
import {
  faviconPath,
  handleAuthorizePost,
  handleRegister,
  handleToken,
  oauthMetadata,
  protectedResourceMetadata,
  requireMcpSession,
  sendAuthorizePage,
} from "./src/auth/http.js";

import express, { Request, Response } from "express";
import { fileURLToPath } from 'url';
import { realpathSync } from 'fs';


log("info", `Starting MySQL MCP server v${version}...`);

// Update tool description to include multi-DB mode and schema-specific permissions
const toolVersion = `MySQL MCP Server [v${process.env.npm_package_version}]`;
let toolDescription = `[${toolVersion}] Run SQL queries against MySQL database`;

if (isMultiDbMode) {
  toolDescription += " (Multi-DB mode enabled)";
}

if (
  ALLOW_INSERT_OPERATION ||
  ALLOW_UPDATE_OPERATION ||
  ALLOW_DELETE_OPERATION ||
  ALLOW_DDL_OPERATION
) {
  // At least one write operation is enabled
  toolDescription += " with support for:";

  if (ALLOW_INSERT_OPERATION) {
    toolDescription += " INSERT,";
  }

  if (ALLOW_UPDATE_OPERATION) {
    toolDescription += " UPDATE,";
  }

  if (ALLOW_DELETE_OPERATION) {
    toolDescription += " DELETE,";
  }

  if (ALLOW_DDL_OPERATION) {
    toolDescription += " DDL,";
  }

  // Remove trailing comma and add READ operations
  toolDescription = toolDescription.replace(/,$/, "") + " and READ operations";

  if (
    Object.keys(SCHEMA_INSERT_PERMISSIONS).length > 0 ||
    Object.keys(SCHEMA_UPDATE_PERMISSIONS).length > 0 ||
    Object.keys(SCHEMA_DELETE_PERMISSIONS).length > 0 ||
    Object.keys(SCHEMA_DDL_PERMISSIONS).length > 0
  ) {
    toolDescription += " (Schema-specific permissions enabled)";
  }
} else {
  // Only read operations are allowed
  toolDescription += " (READ-ONLY)";
}

// Determine if we're in read-only mode (no write operations enabled)
const isReadOnly = !(
  ALLOW_INSERT_OPERATION ||
  ALLOW_UPDATE_OPERATION ||
  ALLOW_DELETE_OPERATION ||
  ALLOW_DDL_OPERATION
);

// @INFO: Add debug logging for configuration
log(
  "info",
  "MySQL Configuration:",
  JSON.stringify(
    {
      ...(process.env.MYSQL_SOCKET_PATH
        ? {
            socketPath: process.env.MYSQL_SOCKET_PATH,
            connectionType: "Unix Socket",
          }
        : {
      host: process.env.MYSQL_HOST || "127.0.0.1",
      port: process.env.MYSQL_PORT || "3306",
      connectionType: "TCP/IP",
          }),
      user: config.mysql.user,
      password: config.mysql.password ? "******" : "not set",
      database: config.mysql.database || "MULTI_DB_MODE",
      ssl: process.env.MYSQL_SSL === "true" ? "enabled" : "disabled",
      sslCA: process.env.MYSQL_SSL_CA || "not set",
      sslCert: process.env.MYSQL_SSL_CERT || "not set",
      sslKey: process.env.MYSQL_SSL_KEY || "not set",
      multiDbMode: isMultiDbMode ? "enabled" : "disabled",
      fundedoceanHost: process.env.MYSQL_HOST_FUNDEDOCEAN || "not set",
      fundedoceanDb: process.env.MYSQL_DB_FUNDEDOCEAN || "not set",
      fundedoceanSsl:
        process.env.MYSQL_SSL_FUNDEDOCEAN === "true" ? "enabled" : "disabled",
    },
    null,
    2,
  ),
);

// Define configuration schema
export const configSchema = z.object({
  debug: z.boolean().default(false).describe("Enable debug logging"),
});

// Export the default function that creates and returns the MCP server
export default function createMcpServer({
  sessionId,
  config,
  brand = DEFAULT_BRAND,
}: {
  sessionId?: string;
  config: z.infer<typeof configSchema>;
  brand?: Brand;
}) {
  // Create the server instance
  const server = new Server(
    {
      name: "MySQL MCP Server",
      version: process.env.npm_package_version || "1.0.0",
    },
    {
      capabilities: {
        resources: {},
        tools: {
          mysql_query: {
            description: toolDescription,
            inputSchema: {
              type: "object",
              properties: {
                sql: {
                  type: "string",
                  description: "The SQL query to execute",
                },
              },
              required: ["sql"],
            },
            annotations: {
              readOnlyHint: isReadOnly,
              idempotentHint: isReadOnly,
              destructiveHint: !isReadOnly,
              openWorldHint: false,
              title: "MySQL Query",
            },
          },
        },
      },
    },
  );

  // Register request handlers for resources
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    try {
      log("info", "Handling ListResourcesRequest");
      const connectionInfo = process.env.MYSQL_SOCKET_PATH
        ? `socket: ${process.env.MYSQL_SOCKET_PATH}`
        : `host: ${process.env.MYSQL_HOST || "localhost"}, port: ${
            process.env.MYSQL_PORT || 3306
          }`;
      log("info", `Connection info: ${connectionInfo}`);

      // Query to get all tables
      const tablesQuery = `
      SELECT
        table_name as name,
        table_schema as \`database\`,
        table_comment as description,
        table_rows as rowCount,
        data_length as dataSize,
        index_length as indexSize,
        create_time as createTime,
        update_time as updateTime
      FROM
        information_schema.tables
      WHERE
        table_schema NOT IN ('information_schema', 'mysql', 'performance_schema', 'sys')
      ORDER BY
        table_schema, table_name
    `;

      const queryResult = (await executeReadOnlyQuery<any>(tablesQuery, brand));
      const tables = JSON.parse(queryResult.content[0].text) as TableRow[];
      log("info", `Found ${tables.length} tables`);

      // Create resources for each table
      const resources = tables.map((table) => ({
        uri: `mysql://tables/${table.name}`,
        name: table.name,
        title: `${table.database}.${table.name}`,
        description:
          table.description ||
          `Table ${table.name} in database ${table.database}`,
        mimeType: "application/json",
      }));

      // Add a resource for the list of tables
      resources.push({
        uri: "mysql://tables",
        name: "Tables",
        title: "MySQL Tables",
        description: "List of all MySQL tables",
        mimeType: "application/json",
      });

      return { resources };
    } catch (error) {
      log("error", "Error in ListResourcesRequest handler:", error);
      throw error;
    }
  });

  // Register request handler for reading resources
  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    try {
      log("info", "Handling ReadResourceRequest:", request.params.uri);

      // Parse the URI to extract table name and optional database name
      const uriParts = request.params.uri.split("/");
      const tableName = uriParts.pop();
      const dbName = uriParts.length > 0 ? uriParts.pop() : null;

      if (!tableName) {
        throw new Error(`Invalid resource URI: ${request.params.uri}`);
      }

      // Modify query to include schema information
      let columnsQuery =
        "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = ?";
      let queryParams = [tableName as string];

      if (dbName) {
        columnsQuery += " AND table_schema = ?";
        queryParams.push(dbName);
      }

      const results = (await executeQuery(
        columnsQuery,
        queryParams,
        brand,
      )) as ColumnRow[];

      return {
        contents: [
          {
            uri: request.params.uri,
            mimeType: "application/json",
            text: JSON.stringify(results, null, 2),
          },
        ],
      };
    } catch (error) {
      log("error", "Error in ReadResourceRequest handler:", error);
      throw error;
    }
  });

  // Register handler for tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    try {
      log("info", "Handling CallToolRequest:", request.params.name);
      if (request.params.name !== "mysql_query") {
        throw new Error(`Unknown tool: ${request.params.name}`);
      }

      const sql = request.params.arguments?.sql as string;
      return await executeReadOnlyQuery(sql, brand);
    } catch (err) {
      const error = err as Error;
      log("error", "Error in CallToolRequest handler:", error);
      return {
        content: [{
          type: "text",
          text: `Error: ${error.message}`
        }],
        isError: true
      };
    }
  });

  // Register handler for listing tools
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    log("info", "Handling ListToolsRequest");

    const toolsResponse = {
      tools: [
        {
          name: "mysql_query",
          description: toolDescription,
          inputSchema: {
            type: "object",
            properties: {
              sql: {
                type: "string",
                description: "The SQL query to execute",
              },
            },
            required: ["sql"],
          },
          annotations: {
            readOnlyHint: isReadOnly,
            idempotentHint: isReadOnly,
            destructiveHint: !isReadOnly,
            openWorldHint: false,
            title: "MySQL Query",
          },
        },
      ],
    };

    log(
      "info",
      "ListToolsRequest response:",
      JSON.stringify(toolsResponse, null, 2),
    );
    return toolsResponse;
  });

  return server;
}

async function testDefaultPool(): Promise<void> {
  log("info", "Attempting to test database connection...");
  const pool = await getPool(STARTUP_BRAND);
  const connection = await pool.getConnection();
  log("info", `Database connection test successful (${STARTUP_BRAND})`);
  connection.release();
}

function registerProcessHandlers(): void {
  const shutdown = async (signal: string): Promise<void> => {
    log("error", `Received ${signal}. Shutting down...`);
    await closeAllPools();
  };

  process.on("SIGINT", async () => {
    try {
      await shutdown("SIGINT");
      process.exit(0);
    } catch (err) {
      log("error", "Error during SIGINT shutdown:", err);
      safeExit(1);
    }
  });

  process.on("SIGTERM", async () => {
    try {
      await shutdown("SIGTERM");
      process.exit(0);
    } catch (err) {
      log("error", "Error during SIGTERM shutdown:", err);
      safeExit(1);
    }
  });

  process.on("uncaughtException", (error) => {
    log("error", "Uncaught exception:", error);
    safeExit(1);
  });

  process.on("unhandledRejection", (reason, promise) => {
    log("error", "Unhandled rejection at:", promise, "reason:", reason);
    safeExit(1);
  });
}

/**
* Checks if the current module is the main module (the entry point of the application).
* This function works for both ES Modules (ESM) and CommonJS.
* @returns {boolean} - True if the module is the main module, false otherwise.
*/
const isMainModule = () => {
  // 1. Standard check for CommonJS
  // `require.main` refers to the application's entry point module.
  // If it's the same as the current `module`, this file was executed directly.
  if (typeof require !== 'undefined' && require.main === module) {
    return true;
  }
  // 2. Check for ES Modules (ESM)
  // `import.meta.url` provides the file URL of the current module.
  // `process.argv[1]` provides the path of the executed script.
  if (typeof import.meta !== 'undefined' && import.meta.url && process.argv[1]) {
    // Convert the `import.meta.url` (e.g., 'file:///path/to/file.js') to a system-standard absolute path.
    const currentModulePath = fileURLToPath(import.meta.url);
    // Resolve `process.argv[1]` (which can be a relative path) to a standard absolute path.
    const mainScriptPath = realpathSync(process.argv[1]);
    // Compare the two standardized absolute paths.
    return currentModulePath === mainScriptPath;
  }
  // Fallback if neither of the above conditions are met.
  return false;
}

// Start the server if this file is being run directly
if (isMainModule()) {
  log("info", "Running in standalone mode");

  (async () => {
    try {
      registerProcessHandlers();
      await testDefaultPool();

      if (IS_REMOTE_MCP) {
        const app = express();
        app.set("trust proxy", true);
        app.use(express.json());
        app.use(express.urlencoded({ extended: false }));
        app.use((req: Request, res: Response, next) => {
          const origin = req.get("Origin");
          if (origin) {
            res.setHeader("Access-Control-Allow-Origin", origin);
            res.setHeader("Vary", "Origin");
          } else {
            res.setHeader("Access-Control-Allow-Origin", "*");
          }
          res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
          res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE");
          if (req.method === "OPTIONS") {
            res.status(204).end();
            return;
          }
          next();
        });

        app.get("/health", (_req: Request, res: Response) => {
          res.status(200).json({ status: "ok" });
        });

        app.get("/", (_req: Request, res: Response) => {
          sendAuthorizePage(res);
        });

        app.get("/authorize", (_req: Request, res: Response) => {
          sendAuthorizePage(res);
        });

        app.post("/authorize", (req: Request, res: Response) => {
          handleAuthorizePost(req, res);
        });

        app.post("/token", (req: Request, res: Response) => {
          handleToken(req, res);
        });

        app.post("/register", (req: Request, res: Response) => {
          handleRegister(req, res);
        });

        const sendAuthMetadata = (req: Request, res: Response) => {
          res.status(200).json(oauthMetadata(req));
        };
        const sendResourceMetadata = (req: Request, res: Response) => {
          res.status(200).json(protectedResourceMetadata(req));
        };
        app.get("/.well-known/oauth-authorization-server", sendAuthMetadata);
        app.get("/.well-known/openid-configuration", sendAuthMetadata);
        app.get("/.well-known/oauth-protected-resource", sendResourceMetadata);
        app.get("/.well-known/oauth-protected-resource/mcp", sendResourceMetadata);

        app.post("/mcp", async (req: Request, res: Response) => {
          const session = requireMcpSession(req, res);
          if (!session) {
            return;
          }
          try {
            const server = createMcpServer({
              config: { debug: false },
              brand: session.platform,
            });
            const transport: StreamableHTTPServerTransport =
              new StreamableHTTPServerTransport({
                sessionIdGenerator: undefined,
              });
            res.on("close", () => {
              log("info", "Request closed");
              transport.close();
              server.close();
            });
            await server.connect(transport);
            await transport.handleRequest(req, res, req.body);
          } catch (error) {
            log("error", "Error handling MCP request:", error);
            if (!res.headersSent) {
              res.status(500).json({
                jsonrpc: "2.0",
                error: {
                  code: -32603,
                  message: (error as any).message,
                },
                id: null,
              });
            }
          }
        });

        app.get("/favicon.ico", (_req: Request, res: Response) => {
          res.sendFile(faviconPath(), (err) => {
            if (err) res.status(404).end();
          });
        });

        app.get("/mcp", async (_req: Request, res: Response) => {
          res.writeHead(405).end(
            JSON.stringify({
              jsonrpc: "2.0",
              error: {
                code: -32000,
                message: "Method not allowed.",
              },
              id: null,
            }),
          );
        });

        app.delete("/mcp", async (_req: Request, res: Response) => {
          res.writeHead(405).end(
            JSON.stringify({
              jsonrpc: "2.0",
              error: {
                code: -32000,
                message: "Method not allowed.",
              },
              id: null,
            }),
          );
        });

        app.listen(PORT, (error) => {
          if (error) {
            console.error("Failed to start server:", error);
            process.exit(1);
          }
          console.log(
            `MCP Stateless Streamable HTTP Server listening on port ${PORT}`,
          );
        });
      } else {
        const mcpServer = createMcpServer({
          config: { debug: false },
          brand: STARTUP_BRAND,
        });
        const transport = new StdioServerTransport();
        await mcpServer.connect(transport);
        log("info", "Server started and listening on stdio");
      }
    } catch (error) {
      log("error", "Server error:", error);
      safeExit(1);
    }
  })();
}
