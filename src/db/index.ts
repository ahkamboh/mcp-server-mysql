import { performance } from "perf_hooks";
import { isMultiDbMode } from "./../config/index.js";

import {
  isDDLAllowedForSchema,
  isInsertAllowedForSchema,
  isUpdateAllowedForSchema,
  isDeleteAllowedForSchema,
} from "./permissions.js";
import { extractSchemaFromQuery, getQueryTypes } from "./utils.js";

import * as mysql2 from "mysql2/promise";
import { log } from "./../utils/index.js";
import {
  Brand,
  DEFAULT_BRAND,
  MYSQL_DISABLE_READ_ONLY_TRANSACTIONS,
  mysqlConfigFor,
} from "./../config/index.js";

// Force read-only mode in multi-DB mode unless explicitly configured otherwise
if (isMultiDbMode && process.env.MULTI_DB_WRITE_MODE !== "true") {
  log("error", "Multi-DB mode detected - enabling read-only mode for safety");
}

// @INFO: Check if running in test mode
const isTestEnvironment = process.env.NODE_ENV === "test" || process.env.VITEST;

// @INFO: Safe way to exit process (not during tests)
function safeExit(code: number): void {
  if (!isTestEnvironment) {
    process.exit(code);
  } else {
    log("error", `[Test mode] Would have called process.exit(${code})`);
  }
}

// @INFO: Lazy load one read-only pool per brand
const pools = new Map<Brand, Promise<mysql2.Pool>>();

const getPool = (brand: Brand = DEFAULT_BRAND): Promise<mysql2.Pool> => {
  const existing = pools.get(brand);
  if (existing) {
    return existing;
  }
  const created = new Promise<mysql2.Pool>((resolve, reject) => {
    try {
      if (brand === "fundedocean" && !process.env.MYSQL_HOST_FUNDEDOCEAN) {
        throw new Error("MYSQL_HOST_FUNDEDOCEAN is not set");
      }
      const pool = mysql2.createPool(mysqlConfigFor(brand));
      log("info", `MySQL pool created for ${brand}`);
      resolve(pool);
    } catch (error) {
      pools.delete(brand);
      log("error", `Error creating MySQL pool for ${brand}:`, error);
      reject(error);
    }
  });
  pools.set(brand, created);
  return created;
};

async function closeAllPools(): Promise<void> {
  const pending = [...pools.values()];
  pools.clear();
  for (const pendingPool of pending) {
    try {
      const pool = await pendingPool;
      await pool.end();
    } catch (err) {
      log("error", "Error closing pool:", err);
    }
  }
}

async function executeQuery<T>(
  sql: string,
  params: string[] = [],
  brand: Brand = DEFAULT_BRAND,
): Promise<T> {
  let connection;
  try {
    const pool = await getPool(brand);
    connection = await pool.getConnection();
    const result = await connection.query(sql, params);
    return (Array.isArray(result) ? result[0] : result) as T;
  } catch (error) {
    log("error", "Error executing query:", error);
    throw error;
  } finally {
    if (connection) {
      connection.release();
      log("error", "Connection released");
    }
  }
}

// @INFO: New function to handle write operations
async function executeWriteQuery<T>(
  sql: string,
  brand: Brand = DEFAULT_BRAND,
): Promise<T> {
  let connection;
  try {
    const pool = await getPool(brand);
    connection = await pool.getConnection();
    log("error", "Write connection acquired");

    // Extract schema for permissions (if needed)
    const schema = extractSchemaFromQuery(sql);

    // @INFO: Begin transaction for write operation
    await connection.beginTransaction();

    try {
      // @INFO: Execute the write query
      const startTime = performance.now();
      const result = await connection.query(sql);
      const endTime = performance.now();
      const duration = endTime - startTime;
      const response = Array.isArray(result) ? result[0] : result;

      // @INFO: Commit the transaction
      await connection.commit();

      // @INFO: Format the response based on operation type
      let responseText;

      // Check the type of query
      const queryTypes = await getQueryTypes(sql);
      const isUpdateOperation = queryTypes.some((type) =>
        ["update"].includes(type),
      );
      const isInsertOperation = queryTypes.some((type) =>
        ["insert"].includes(type),
      );
      const isDeleteOperation = queryTypes.some((type) =>
        ["delete"].includes(type),
      );
      const isDDLOperation = queryTypes.some((type) =>
        ["create", "alter", "drop", "truncate"].includes(type),
      );

      // @INFO: Type assertion for ResultSetHeader which has affectedRows, insertId, etc.
      if (isInsertOperation) {
        const resultHeader = response as mysql2.ResultSetHeader;
        responseText = `Insert successful on schema '${schema || "default"}'. Affected rows: ${resultHeader.affectedRows}, Last insert ID: ${resultHeader.insertId}`;
      } else if (isUpdateOperation) {
        const resultHeader = response as mysql2.ResultSetHeader;
        responseText = `Update successful on schema '${schema || "default"}'. Affected rows: ${resultHeader.affectedRows}, Changed rows: ${resultHeader.changedRows || 0}`;
      } else if (isDeleteOperation) {
        const resultHeader = response as mysql2.ResultSetHeader;
        responseText = `Delete successful on schema '${schema || "default"}'. Affected rows: ${resultHeader.affectedRows}`;
      } else if (isDDLOperation) {
        responseText = `DDL operation successful on schema '${schema || "default"}'.`;
      } else {
        responseText = JSON.stringify(response, null, 2);
      }

      return {
        content: [
          {
            type: "text",
            text: responseText,
          },
          {
            type: "text",
            text: `Query execution time: ${duration.toFixed(2)} ms`,
          },
        ],
        isError: false,
      } as T;
    } catch (error: unknown) {
      // @INFO: Rollback on error
      log("error", "Error executing write query:", error);
      await connection.rollback();

      return {
        content: [
          {
            type: "text",
            text: `Error executing write operation: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      } as T;
    }
  } catch (error: unknown) {
    log("error", "Error in write operation transaction:", error);
    return {
      content: [
        {
          type: "text",
          text: `Database connection error: ${error instanceof Error ? error.message : String(error)}`,
        },
      ],
      isError: true,
    } as T;
  } finally {
    if (connection) {
      connection.release();
      log("error", "Write connection released");
    }
  }
}

async function executeReadOnlyQuery<T>(
  sql: string,
  brand: Brand = DEFAULT_BRAND,
): Promise<T> {
  let connection;
  try {
    // Check the type of query
    const queryTypes = await getQueryTypes(sql);

    // Get schema for permission checking
    const schema = extractSchemaFromQuery(sql);

    const isUpdateOperation = queryTypes.some((type) =>
      ["update"].includes(type),
    );
    const isInsertOperation = queryTypes.some((type) =>
      ["insert"].includes(type),
    );
    const isDeleteOperation = queryTypes.some((type) =>
      ["delete"].includes(type),
    );
    const isDDLOperation = queryTypes.some((type) =>
      ["create", "alter", "drop", "truncate"].includes(type),
    );

    // Check schema-specific permissions
    if (isInsertOperation && !isInsertAllowedForSchema(schema)) {
      log(
        "error",
        `INSERT operations are not allowed for schema '${schema || "default"}'. Configure SCHEMA_INSERT_PERMISSIONS.`,
      );
      return {
        content: [
          {
            type: "text",
            text: `Error: INSERT operations are not allowed for schema '${schema || "default"}'. Ask the administrator to update SCHEMA_INSERT_PERMISSIONS.`,
          },
        ],
        isError: true,
      } as T;
    }

    if (isUpdateOperation && !isUpdateAllowedForSchema(schema)) {
      log(
        "error",
        `UPDATE operations are not allowed for schema '${schema || "default"}'. Configure SCHEMA_UPDATE_PERMISSIONS.`,
      );
      return {
        content: [
          {
            type: "text",
            text: `Error: UPDATE operations are not allowed for schema '${schema || "default"}'. Ask the administrator to update SCHEMA_UPDATE_PERMISSIONS.`,
          },
        ],
        isError: true,
      } as T;
    }

    if (isDeleteOperation && !isDeleteAllowedForSchema(schema)) {
      log(
        "error",
        `DELETE operations are not allowed for schema '${schema || "default"}'. Configure SCHEMA_DELETE_PERMISSIONS.`,
      );
      return {
        content: [
          {
            type: "text",
            text: `Error: DELETE operations are not allowed for schema '${schema || "default"}'. Ask the administrator to update SCHEMA_DELETE_PERMISSIONS.`,
          },
        ],
        isError: true,
      } as T;
    }

    if (isDDLOperation && !isDDLAllowedForSchema(schema)) {
      log(
        "error",
        `DDL operations are not allowed for schema '${schema || "default"}'. Configure SCHEMA_DDL_PERMISSIONS.`,
      );
      return {
        content: [
          {
            type: "text",
            text: `Error: DDL operations are not allowed for schema '${schema || "default"}'. Ask the administrator to update SCHEMA_DDL_PERMISSIONS.`,
          },
        ],
        isError: true,
      } as T;
    }

    // For write operations that are allowed, use executeWriteQuery
    if (
      (isInsertOperation && isInsertAllowedForSchema(schema)) ||
      (isUpdateOperation && isUpdateAllowedForSchema(schema)) ||
      (isDeleteOperation && isDeleteAllowedForSchema(schema)) ||
      (isDDLOperation && isDDLAllowedForSchema(schema))
    ) {
      return executeWriteQuery(sql, brand);
    }

    // For read-only operations, continue with the original logic
    const pool = await getPool(brand);
    connection = await pool.getConnection();
    log("error", "Read-only connection acquired");

    // Set read-only mode (unless disabled via environment variable)
    if (!MYSQL_DISABLE_READ_ONLY_TRANSACTIONS) {
      await connection.query("SET SESSION TRANSACTION READ ONLY");
    } else {
      log("info", "Read-only transactions disabled via MYSQL_DISABLE_READ_ONLY_TRANSACTIONS=true");
    }

    // Begin transaction
    await connection.beginTransaction();

    try {
      // Execute query - in multi-DB mode, we may need to handle USE statements specially
      const startTime = performance.now();
      const result = await connection.query(sql);
      const endTime = performance.now();
      const duration = endTime - startTime;
      const rows = Array.isArray(result) ? result[0] : result;

      // Rollback transaction (since it's read-only)
      await connection.rollback();

      // Reset to read-write mode (only if we set it to read-only)
      if (!MYSQL_DISABLE_READ_ONLY_TRANSACTIONS) {
        await connection.query("SET SESSION TRANSACTION READ WRITE");
      }

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(rows, null, 2),
          },
          {
            type: "text",
            text: `Query execution time: ${duration.toFixed(2)} ms`,
          },
        ],
        isError: false,
      } as T;
    } catch (error) {
      // Rollback transaction on query error
      log("error", "Error executing read-only query:", error);
      await connection.rollback();
      throw error;
    }
  } catch (error) {
    // Ensure we rollback and reset transaction mode on any error
    log("error", "Error in read-only query transaction:", error);
    try {
      if (connection) {
        await connection.rollback();
        // Reset to read-write mode (only if we set it to read-only)
        if (!MYSQL_DISABLE_READ_ONLY_TRANSACTIONS) {
          await connection.query("SET SESSION TRANSACTION READ WRITE");
        }
      }
    } catch (cleanupError) {
      // Ignore errors during cleanup
      log("error", "Error during cleanup:", cleanupError);
    }
    throw error;
  } finally {
    if (connection) {
      connection.release();
      log("error", "Read-only connection released");
    }
  }
}

export {
  isTestEnvironment,
  safeExit,
  executeQuery,
  getPool,
  executeWriteQuery,
  executeReadOnlyQuery,
  closeAllPools,
};
