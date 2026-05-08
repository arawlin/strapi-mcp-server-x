#!/usr/bin/env node

/**
 * Strapi MCP Server
 * Version 2.6.0
 * 
 * Version History:
 * 2.6.0 - Enhanced Validation & Debugging Update
 * - Implemented structured error handling with McpError and ErrorCode
 * - Added comprehensive Zod validation for runtime type safety
 * - Integrated comprehensive logging system with request tracking
 * - Added debug mode configuration with environment variables
 * - Removed unused prompt handlers for cleaner codebase
 * - Updated all dependencies to latest versions
 * - Added DEBUGGING.md guide for development workflow
 * 
 * 2.5.1 - Documentation & Configuration Enhancement
 * - Added detailed project documentation to CLAUDE.md
 * - Expanded configuration options with version support
 * - Improved error messaging and troubleshooting guides
 * - Enhanced REST API documentation and examples
 * - Added best practices for content management
 * 
 * 2.2.0 - Security & Version Handling Update
 * - Added strict write protection policy
 * - Enhanced version format support (5.*, 4.1.5, v4, etc.)
 * - Integrated documentation into server capabilities
 * - Removed connect prompt (now in capabilities)
 * - Improved error handling and validation
 * 
 * 2.1.0 - Previous Release
 * - Basic Strapi integration
 * - Server configuration
 * - Content type handling
 * - Media upload support
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
    McpError,
    ErrorCode,
} from "@modelcontextprotocol/sdk/types.js";
import fetch, { Response, RequestInit } from 'node-fetch';
import FormData from 'form-data';
import sharp from 'sharp';
import { readFileSync } from 'fs';
import { readFile, stat } from 'fs/promises';
import { homedir } from 'os';
import { basename, extname, join } from 'path';
import qs from 'qs';
import { z } from 'zod';
import { randomUUID } from 'crypto';

// ===========================================
// Comprehensive Logging and Debugging System
// ===========================================

/**
 * Log levels for structured logging
 */
enum LogLevel {
    ERROR = 0,
    WARN = 1,
    INFO = 2,
    DEBUG = 3,
    TRACE = 4
}

/**
 * Interface for log entry structure
 */
interface LogEntry {
    timestamp: string;
    level: string;
    requestId?: string;
    operation?: string;
    server?: string;
    endpoint?: string;
    method?: string;
    duration?: number;
    error?: boolean;
    message: string;
    context?: Record<string, any>;
    sanitized?: boolean;
}

/**
 * Configuration for the logging system
 */
interface LogConfig {
    level: LogLevel;
    enableRequestTracking: boolean;
    enablePerformanceMonitoring: boolean;
    sanitizeData: boolean;
    maxLogLength: number;
    includeStackTrace: boolean;
}

/**
 * Comprehensive logging class with structured output, request tracking, and performance monitoring
 */
class McpLogger {
    private config: LogConfig;
    private activeRequests: Map<string, { start: number; operation: string; server?: string }>;

    constructor() {
        this.config = this.loadConfig();
        this.activeRequests = new Map();
        
        // Log startup configuration
        this.info('Logger initialized', {
            level: LogLevel[this.config.level],
            requestTracking: this.config.enableRequestTracking,
            performanceMonitoring: this.config.enablePerformanceMonitoring,
            sanitization: this.config.sanitizeData
        });
    }

    /**
     * Load configuration from environment variables
     */
    private loadConfig(): LogConfig {
        const logLevelStr = process.env.MCP_LOG_LEVEL || 'INFO';
        const logLevel = LogLevel[logLevelStr.toUpperCase() as keyof typeof LogLevel] ?? LogLevel.INFO;
        
        return {
            level: logLevel,
            enableRequestTracking: process.env.MCP_ENABLE_REQUEST_TRACKING !== 'false',
            enablePerformanceMonitoring: process.env.MCP_ENABLE_PERFORMANCE_MONITORING !== 'false',
            sanitizeData: process.env.MCP_SANITIZE_DATA !== 'false',
            maxLogLength: parseInt(process.env.MCP_MAX_LOG_LENGTH || '10000'),
            includeStackTrace: process.env.MCP_INCLUDE_STACK_TRACE === 'true'
        };
    }

    /**
     * Generate a unique request ID
     */
    generateRequestId(): string {
        return randomUUID();
    }

    /**
     * Start tracking a request
     */
    startRequest(requestId: string, operation: string, server?: string): void {
        if (!this.config.enableRequestTracking) return;
        
        this.activeRequests.set(requestId, {
            start: Date.now(),
            operation,
            server
        });
        
        this.debug(`Request started: ${operation}`, {
            requestId,
            operation,
            server
        });
    }

    /**
     * End tracking a request and log performance metrics
     */
    endRequest(requestId: string, success: boolean = true, error?: Error): void {
        if (!this.config.enableRequestTracking) return;
        
        const requestData = this.activeRequests.get(requestId);
        if (!requestData) return;
        
        const duration = Date.now() - requestData.start;
        this.activeRequests.delete(requestId);
        
        const logData = {
            requestId,
            operation: requestData.operation,
            server: requestData.server,
            duration,
            success,
            error: !success
        };
        
        if (success) {
            this.info(`Request completed: ${requestData.operation}`, logData);
        } else {
            this.error(`Request failed: ${requestData.operation}`, logData, error);
        }
        
        // Log performance warning for slow requests
        if (this.config.enablePerformanceMonitoring && duration > 5000) {
            this.warn(`Slow request detected: ${requestData.operation} took ${duration}ms`, logData);
        }
    }

    /**
     * Log API call performance
     */
    logApiCall(
        requestId: string,
        method: string,
        endpoint: string,
        duration: number,
        status: number,
        server?: string
    ): void {
        if (!this.config.enablePerformanceMonitoring) return;
        
        const logData = {
            requestId,
            method,
            endpoint,
            duration,
            status,
            server,
            success: status >= 200 && status < 300
        };
        
        if (status >= 400) {
            this.warn(`API call failed: ${method} ${endpoint}`, logData);
        } else if (duration > 2000) {
            this.warn(`Slow API call: ${method} ${endpoint} took ${duration}ms`, logData);
        } else {
            this.debug(`API call: ${method} ${endpoint}`, logData);
        }
    }

    /**
     * Sanitize sensitive data from logs
     */
    private sanitizeData(data: any): any {
        if (!this.config.sanitizeData) return data;
        
        const sensitiveKeys = [
            'password', 'token', 'jwt', 'api_key', 'secret',
            'authorization', 'auth', 'credentials', 'key'
        ];
        
        const sanitize = (obj: any): any => {
            if (typeof obj !== 'object' || obj === null) return obj;
            
            if (Array.isArray(obj)) {
                return obj.map(item => sanitize(item));
            }
            
            const sanitized: any = {};
            for (const [key, value] of Object.entries(obj)) {
                const lowerKey = key.toLowerCase();
                if (sensitiveKeys.some(sensitive => lowerKey.includes(sensitive))) {
                    sanitized[key] = '[REDACTED]';
                } else if (typeof value === 'object' && value !== null) {
                    sanitized[key] = sanitize(value);
                } else {
                    sanitized[key] = value;
                }
            }
            return sanitized;
        };
        
        return sanitize(data);
    }

    /**
     * Create a structured log entry
     */
    private createLogEntry(
        level: LogLevel,
        message: string,
        context?: Record<string, any>,
        error?: Error
    ): LogEntry {
        const entry: LogEntry = {
            timestamp: new Date().toISOString(),
            level: LogLevel[level],
            message: message.length > this.config.maxLogLength 
                ? message.substring(0, this.config.maxLogLength) + '...' 
                : message,
            sanitized: this.config.sanitizeData
        };
        
        if (context) {
            entry.context = this.sanitizeData(context);
            
            // Extract common fields for easier filtering
            if (context.requestId) entry.requestId = context.requestId;
            if (context.operation) entry.operation = context.operation;
            if (context.server) entry.server = context.server;
            if (context.endpoint) entry.endpoint = context.endpoint;
            if (context.method) entry.method = context.method;
            if (context.duration) entry.duration = context.duration;
            if (context.error) entry.error = context.error;
        }
        
        if (error) {
            entry.context = entry.context || {};
            entry.context.error = {
                name: error.name,
                message: error.message,
                ...(this.config.includeStackTrace && { stack: error.stack })
            };
            entry.error = true;
        }
        
        return entry;
    }

    /**
     * Output log entry to stderr (not stdout to avoid interfering with MCP protocol)
     */
    private output(entry: LogEntry): void {
        if (this.shouldLog(LogLevel[entry.level as keyof typeof LogLevel])) {
            process.stderr.write(JSON.stringify(entry) + '\n');
        }
    }

    /**
     * Check if we should log at the given level
     */
    private shouldLog(level: LogLevel): boolean {
        return level <= this.config.level;
    }

    /**
     * Log error message
     */
    error(message: string, context?: Record<string, any>, error?: Error): void {
        this.output(this.createLogEntry(LogLevel.ERROR, message, context, error));
    }

    /**
     * Log warning message
     */
    warn(message: string, context?: Record<string, any>): void {
        this.output(this.createLogEntry(LogLevel.WARN, message, context));
    }

    /**
     * Log info message
     */
    info(message: string, context?: Record<string, any>): void {
        this.output(this.createLogEntry(LogLevel.INFO, message, context));
    }

    /**
     * Log debug message
     */
    debug(message: string, context?: Record<string, any>): void {
        this.output(this.createLogEntry(LogLevel.DEBUG, message, context));
    }

    /**
     * Log trace message
     */
    trace(message: string, context?: Record<string, any>): void {
        this.output(this.createLogEntry(LogLevel.TRACE, message, context));
    }

    /**
     * Log validation errors with detailed context
     */
    logValidationError(toolName: string, error: z.ZodError, input: unknown, requestId?: string): void {
        const context = {
            requestId,
            toolName,
            input: this.sanitizeData(input),
            validationErrors: error.issues.map((err) => ({
                path: err.path.join('.'),
                message: err.message,
                code: err.code,
                received: 'input' in err ? err.input : undefined
            }))
        };
        
        this.error(`Validation failed for tool: ${toolName}`, context);
    }

    /**
     * Log tool execution with timing
     */
    logToolExecution(
        toolName: string,
        args: unknown,
        requestId: string,
        duration: number,
        success: boolean,
        error?: Error
    ): void {
        const context = {
            requestId,
            toolName,
            args: this.sanitizeData(args),
            duration,
            success,
            error: !success
        };
        
        if (success) {
            this.info(`Tool executed successfully: ${toolName}`, context);
        } else {
            this.error(`Tool execution failed: ${toolName}`, context, error);
        }
    }

    /**
     * Get current configuration for debugging
     */
    getConfig(): LogConfig {
        return { ...this.config };
    }

    /**
     * Get active requests for debugging
     */
    getActiveRequests(): Array<{ requestId: string; operation: string; duration: number; server?: string }> {
        const now = Date.now();
        return Array.from(this.activeRequests.entries()).map(([requestId, data]) => ({
            requestId,
            operation: data.operation,
            duration: now - data.start,
            server: data.server
        }));
    }
}

// Create global logger instance
const logger = new McpLogger();

// Define version info type
type VersionInfo = {
    id_field: string;
    data_structure: string;
    attributes: string;
    auth_pattern: string;
    key_features: string[];
    breaking_changes: {
        database: string[];
        api: string[];
        configuration: string[];
        plugins: string[];
    };
    migration_flags: {
        rest_api: string;
        graphql: string;
    };
    compatibility_notes: string[];
};

type StrapiVersionDifferences = {
    v4: VersionInfo;
    v5: VersionInfo;
};

// Zod Schemas for Tool Input Validation
// ===========================================

// Schema for strapi_list_servers tool (no parameters)
const ListServersSchema = z.object({}).strict();

// Schema for strapi_get_content_types tool
const GetContentTypesSchema = z.object({
    server: z.string().min(1, "Server name is required and cannot be empty")
}).strict();

// Schema for strapi_get_components tool
const GetComponentsSchema = z.object({
    server: z.string().min(1, "Server name is required and cannot be empty"),
    page: z.union([
        z.number().int().min(1, "Page must be a positive integer"),
        z.string().transform((str, ctx) => {
            const num = parseInt(str);
            if (isNaN(num) || num < 1) {
                ctx.addIssue({
                    code: "custom",
                    message: "Page must be a positive integer"
                });
                return z.NEVER;
            }
            return num;
        })
    ]).optional().default(1),
    pageSize: z.union([
        z.number().int().min(1, "Page size must be a positive integer"),
        z.string().transform((str, ctx) => {
            const num = parseInt(str);
            if (isNaN(num) || num < 1) {
                ctx.addIssue({
                    code: "custom",
                    message: "Page size must be a positive integer"
                });
                return z.NEVER;
            }
            return num;
        })
    ]).optional().default(25)
}).strict();

// Schema for strapi_rest tool
const RestSchema = z.object({
    server: z.string().min(1, "Server name is required and cannot be empty"),
    endpoint: z.string()
        .min(1, "Endpoint is required and cannot be empty")
        .refine(
            (value) => !value.includes('?'),
            {
                message: "Endpoint must not include query strings. Pass query parameters via params."
            }
        ),
    method: z.enum(["GET", "POST", "PUT", "DELETE"], {
        error: "Method must be one of: GET, POST, PUT, DELETE"
    }).optional().default("GET"),
    params: z.union([
        z.record(z.string(), z.any()),
        z.string().transform((str, ctx) => {
            try {
                return JSON.parse(str);
            } catch (e) {
                ctx.addIssue({
                    code: "custom",
                    message: "Params must be a valid JSON object or object"
                });
                return z.NEVER;
            }
        })
    ]).optional(),
    body: z.union([
        z.record(z.string(), z.any()),
        z.string().transform((str, ctx) => {
            try {
                return JSON.parse(str);
            } catch (e) {
                ctx.addIssue({
                    code: "custom",
                    message: "Body must be either a JSON object or a JSON string that parses to an object. File-path shortcuts like '@/tmp/payload.json' are not supported."
                });
                return z.NEVER;
            }
        })
    ]).optional(),
    userAuthorized: z.union([
        z.boolean(),
        z.string().transform((str, ctx) => {
            if (str === "true") return true;
            if (str === "false") return false;
            ctx.addIssue({
                code: "custom",
                message: "userAuthorized must be boolean true/false or string 'true'/'false'"
            });
            return z.NEVER;
        })
    ]).optional().default(false)
}).strict().refine(
    (data) => {
        // For write operations, ensure userAuthorized is explicitly set to true
        if (["POST", "PUT", "DELETE"].includes(data.method) && !data.userAuthorized) {
            return false;
        }
        return true;
    },
    {
        message: "Write operations (POST, PUT, DELETE) require explicit user authorization (userAuthorized: true)",
        path: ["userAuthorized"]
    }
);

// Schema for media metadata
const MediaMetadataSchema = z.object({
    name: z.string().optional(),
    caption: z.string().optional(),
    alternativeText: z.string().optional(),
    description: z.string().optional()
}).strict();

// Schema for strapi_upload_media tool
const UploadMediaSchema = z.object({
    server: z.string().min(1, "Server name is required and cannot be empty"),
    url: z.url({ error: "Must be a valid URL" }).optional(),
    localPath: z.string().trim().min(1, "localPath cannot be empty").optional(),
    format: z.enum(["jpeg", "png", "webp", "original"], {
        error: "Format must be one of: jpeg, png, webp, original"
    }).optional().default("original"),
    quality: z.union([
        z.number().int().min(1, "Quality must be between 1 and 100").max(100, "Quality must be between 1 and 100"),
        z.string().transform((str, ctx) => {
            const num = parseInt(str);
            if (isNaN(num) || num < 1 || num > 100) {
                ctx.addIssue({
                    code: "custom",
                    message: "Quality must be between 1 and 100"
                });
                return z.NEVER;
            }
            return num;
        })
    ]).optional().default(80),
    metadata: MediaMetadataSchema.optional(),
    userAuthorized: z.union([
        z.boolean(),
        z.string().transform((str, ctx) => {
            if (str === "true") return true;
            if (str === "false") return false;
            ctx.addIssue({
                code: "custom",
                message: "userAuthorized must be boolean true/false or string 'true'/'false'"
            });
            return z.NEVER;
        })
    ]).optional().default(false)
}).strict().superRefine((data, ctx) => {
    const hasUrl = typeof data.url === 'string';
    const hasLocalPath = typeof data.localPath === 'string';

    if (hasUrl === hasLocalPath) {
        const message = "Provide exactly one source: either url or localPath";
        ctx.addIssue({
            code: "custom",
            message,
            path: ["url"]
        });
        ctx.addIssue({
            code: "custom",
            message,
            path: ["localPath"]
        });
    }

    if (!data.userAuthorized) {
        ctx.addIssue({
            code: "custom",
            message: "Media upload operations require explicit user authorization (userAuthorized: true)",
            path: ["userAuthorized"]
        });
    }
});

// Collection of all schemas for easy access
const ToolSchemas = {
    strapi_list_servers: ListServersSchema,
    strapi_get_content_types: GetContentTypesSchema,
    strapi_get_components: GetComponentsSchema,
    strapi_rest: RestSchema,
    strapi_upload_media: UploadMediaSchema
} as const;

// Validation helper function
function validateToolInput<T extends keyof typeof ToolSchemas>(
    toolName: T,
    input: unknown,
    requestId?: string
): z.infer<typeof ToolSchemas[T]> {
    const schema = ToolSchemas[toolName];
    try {
        logger.debug(`Validating input for tool: ${toolName}`, {
            requestId,
            toolName,
            inputType: typeof input,
            hasInput: input !== undefined
        });

        const result = schema.parse(input);

        logger.debug(`Validation successful for tool: ${toolName}`, {
            requestId,
            toolName
        });

        return result as z.infer<typeof ToolSchemas[T]>;
    } catch (error) {
        if (error instanceof z.ZodError) {
            logger.logValidationError(toolName, error, input, requestId);
            
            const errorMessages = error.issues.map((err) => {
                const path = err.path.length > 0 ? `${err.path.join('.')}: ` : '';
                return `${path}${err.message}`;
            });
            throw new Error(`Validation failed for ${toolName}:\n${errorMessages.join('\n')}`);
        }
        
        logger.error(`Unexpected validation error for tool: ${toolName}`, {
            requestId,
            toolName,
            errorType: error instanceof Error ? error.constructor.name : typeof error
        }, error instanceof Error ? error : undefined);
        
        throw error;
    }
}

// Helper to safely access Zod internal definition (compatible with v3 and v4)
function getZodDef(zodType: any): any {
    // Zod v4 uses _zod.def, Zod v3 uses _def
    const type = zodType as any;
    return type._zod?.def ?? type._def ?? {};
}

function getZodDefType(zodType: z.ZodTypeAny): string | undefined {
    const def = getZodDef(zodType);
    return def.type ?? def.typeName;
}

function getCheckDef(check: any): any {
    return getZodDef(check);
}

// Helper function to convert a single Zod type to JSON Schema type
function zodTypeToJsonSchema(zodType: z.ZodTypeAny): any {
    const def = getZodDef(zodType);
    const defType = getZodDefType(zodType);

    // Unwrap transform wrappers to publish the expected input schema
    if (defType === 'pipe') {
        const inputSchema = def.in ?? def.innerType;
        if (inputSchema) {
            return zodTypeToJsonSchema(inputSchema);
        }
    }

    // Legacy support for older Zod effects wrappers
    if (def.typeName === 'ZodEffects' || (zodType as any)._zod?.typeName === 'ZodEffects') {
        const innerSchema = def.schema ?? def.innerType ?? def.in;
        if (innerSchema) {
            return zodTypeToJsonSchema(innerSchema);
        }
    }

    if (zodType instanceof z.ZodUnion || defType === 'union') {
        return unionToJsonSchema(zodType);
    }

    if (zodType instanceof z.ZodString || defType === 'string') {
        const schema: any = { type: "string" };
        const checks = def.checks ?? [];

        for (const check of checks) {
            const checkDef = getCheckDef(check);

            if (checkDef.kind === 'min' && typeof checkDef.value === 'number') {
                schema.minLength = checkDef.value;
            }
            if (checkDef.check === 'min_length' && typeof checkDef.minimum === 'number') {
                schema.minLength = checkDef.minimum;
            }
            if (checkDef.kind === 'max' && typeof checkDef.value === 'number') {
                schema.maxLength = checkDef.value;
            }
            if (checkDef.check === 'max_length' && typeof checkDef.maximum === 'number') {
                schema.maxLength = checkDef.maximum;
            }

            const isUrlFormat =
                checkDef.kind === 'url' ||
                (checkDef.check === 'string_format' && (checkDef.format === 'url' || checkDef.format === 'uri')) ||
                checkDef.format === 'url' ||
                checkDef.format === 'uri';

            if (isUrlFormat) {
                schema.format = "uri";
            }
        }

        if (def.format === 'url' || def.format === 'uri') {
            schema.format = "uri";
        }

        return schema;
    }

    if (zodType instanceof z.ZodNumber || defType === 'number') {
        const schema: any = { type: "number" };
        const checks = def.checks ?? [];

        for (const check of checks) {
            const checkDef = getCheckDef(check);

            if (checkDef.kind === 'min' && typeof checkDef.value === 'number') {
                schema.minimum = checkDef.value;
            }
            if (checkDef.kind === 'max' && typeof checkDef.value === 'number') {
                schema.maximum = checkDef.value;
            }
            if (checkDef.kind === 'int') {
                schema.type = "integer";
            }

            if (checkDef.check === 'greater_than' && typeof checkDef.value === 'number') {
                if (checkDef.inclusive) {
                    schema.minimum = checkDef.value;
                } else {
                    schema.exclusiveMinimum = checkDef.value;
                }
            }
            if (checkDef.check === 'less_than' && typeof checkDef.value === 'number') {
                if (checkDef.inclusive) {
                    schema.maximum = checkDef.value;
                } else {
                    schema.exclusiveMaximum = checkDef.value;
                }
            }
            if (checkDef.check === 'multiple_of' && typeof checkDef.value === 'number') {
                schema.multipleOf = checkDef.value;
            }

            if (checkDef.check === 'number_format' && typeof checkDef.format === 'string') {
                if (checkDef.format.toLowerCase().includes('int')) {
                    schema.type = "integer";
                }
            }
        }

        return schema;
    }

    if (zodType instanceof z.ZodBoolean || defType === 'boolean') {
        return { type: "boolean" };
    }

    if (zodType instanceof z.ZodEnum || defType === 'enum') {
        // Zod v4: entries, Zod v3: values
        const values = def.entries ? Object.keys(def.entries) : def.values;
        return { type: "string", enum: values };
    }

    if (defType === 'literal') {
        const literalType = typeof def.value;
        return {
            type: literalType === 'number' || literalType === 'boolean' || literalType === 'string' ? literalType : undefined,
            const: def.value
        };
    }

    if (zodType instanceof z.ZodRecord || defType === 'record') {
        return { type: "object", additionalProperties: true };
    }

    if (zodType instanceof z.ZodObject || defType === 'object') {
        return { type: "object", additionalProperties: true };
    }

    if (defType === 'array') {
        return { type: "array" };
    }

    return { type: "object", additionalProperties: true };
}

// Helper function to process union types into JSON Schema oneOf
function unionToJsonSchema(unionType: z.ZodTypeAny): any {
    const def = getZodDef(unionType);
    const options = (def.options ?? []) as z.ZodTypeAny[];

    if (!Array.isArray(options) || options.length === 0) {
        return { type: "object", additionalProperties: true };
    }

    const schemas = options.map(opt => zodTypeToJsonSchema(unwrapZodType(opt)));

    // Deduplicate schemas by type
    const uniqueSchemas: any[] = [];
    const seenTypes = new Set<string>();

    for (const schema of schemas) {
        const key = JSON.stringify(schema);
        if (!seenTypes.has(key)) {
            seenTypes.add(key);
            uniqueSchemas.push(schema);
        }
    }

    const collapsedSchema = collapseSimpleUnionSchemas(uniqueSchemas);
    if (collapsedSchema) {
        return collapsedSchema;
    }

    // If only one unique schema, return it directly
    if (uniqueSchemas.length === 1) {
        return uniqueSchemas[0];
    }

    return { oneOf: uniqueSchemas };
}

function collapseSimpleUnionSchemas(schemas: any[]): any | null {
    if (!Array.isArray(schemas) || schemas.length === 0) {
        return null;
    }

    const typeCounts = new Map<string, number>();

    for (const schema of schemas) {
        if (!schema || typeof schema !== 'object' || Array.isArray(schema)) {
            return null;
        }

        if (schema.oneOf || schema.anyOf || schema.allOf || schema.$ref || typeof schema.type !== 'string') {
            return null;
        }

        typeCounts.set(schema.type, (typeCounts.get(schema.type) ?? 0) + 1);
    }

    for (const count of typeCounts.values()) {
        if (count > 1) {
            return null;
        }
    }

    const merged: any = {};
    const otherKeys = new Set<string>();

    for (const schema of schemas) {
        for (const key of Object.keys(schema)) {
            if (key !== 'type') {
                otherKeys.add(key);
            }
        }
    }

    for (const key of otherKeys) {
        const values = schemas
            .filter(schema => key in schema)
            .map(schema => JSON.stringify(schema[key]));

        if (values.length === 0) {
            continue;
        }

        const distinctValues = [...new Set(values)];
        if (distinctValues.length > 1) {
            return null;
        }

        merged[key] = JSON.parse(distinctValues[0]);
    }

    const types = [...typeCounts.keys()];
    merged.type = types.length === 1 ? types[0] : types;

    return merged;
}

// Helper function to unwrap nested Zod types (Optional, Default, etc.)
function unwrapZodType(zodType: z.ZodTypeAny): z.ZodTypeAny {
    const def = getZodDef(zodType);

    if (zodType instanceof z.ZodOptional || def.type === 'optional') {
        return unwrapZodType(def.innerType);
    }

    if (zodType instanceof z.ZodDefault || def.type === 'default') {
        return unwrapZodType(def.innerType);
    }

    if (def.type === 'pipe' && def.in) {
        return unwrapZodType(def.in);
    }

    return zodType;
}

// Helper function to convert Zod schema to JSON schema for MCP compatibility
function zodToJsonSchema(schema: z.ZodSchema): any {
    if (schema instanceof z.ZodObject) {
        const shape = schema.shape;
        const properties: any = {};
        const required: string[] = [];

        for (const [key, value] of Object.entries(shape)) {
            const zodValue = value as z.ZodTypeAny;
            const unwrapped = unwrapZodType(zodValue);

            // Check if it's a union type (after unwrapping Optional/Default)
            if (unwrapped instanceof z.ZodUnion || getZodDef(unwrapped).type === 'union') {
                properties[key] = unionToJsonSchema(unwrapped);
            } else {
                properties[key] = zodTypeToJsonSchema(unwrapped);
            }

            // Only mark as required if not optional and not having a default
            const valueDef = getZodDef(zodValue);
            const isOptional =
                zodValue instanceof z.ZodOptional ||
                zodValue instanceof z.ZodDefault ||
                valueDef.type === 'optional' ||
                valueDef.type === 'default';

            if (!isOptional) {
                required.push(key);
            }
        }

        return {
            $schema: "http://json-schema.org/draft-07/schema#",
            type: "object",
            properties,
            required,
            additionalProperties: false
        };
    }

    return {
        $schema: "http://json-schema.org/draft-07/schema#",
        type: "object",
        properties: {},
        required: [],
        additionalProperties: false
    };
}

// Define version differences for reference
const STRAPI_VERSION_DIFFERENCES: StrapiVersionDifferences = {
    "v4": {
        "id_field": "id",
        "data_structure": "Uses data wrapper structure",
        "attributes": "Nested under attributes object",
        "auth_pattern": "Classic JWT pattern",
        "key_features": [
            "Numeric IDs",
            "Nested attribute structure",
            "Data wrapper in responses",
            "Traditional REST patterns",
            "External i18n plugin"
        ],
        "breaking_changes": {
            "database": [],
            "api": [],
            "configuration": [],
            "plugins": []
        },
        "migration_flags": {
            "rest_api": "N/A",
            "graphql": "N/A"
        },
        "compatibility_notes": [
            "Uses SQLite3 for SQLite support",
            "Supports MySQL v5",
            "Uses traditional lifecycle hooks",
            "External i18n plugin required"
        ]
    },
    "v5": {
        "id_field": "documentId",
        "data_structure": "Direct access without wrapper",
        "attributes": "Direct access at root level",
        "auth_pattern": "Enhanced JWT with improved security",
        "key_features": [
            "Document-based IDs",
            "Flat data structure",
            "Direct attribute access",
            "Improved REST patterns",
            "Better error handling",
            "Integrated i18n support",
            "New Document Service API",
            "Enhanced database support"
        ],
        "breaking_changes": {
            "database": [
                "Only better-sqlite3 supported for SQLite",
                "Only mysql2 supported for MySQL",
                "MySQL v5 no longer supported",
                "New lifecycle hooks system"
            ],
            "api": [
                "New REST API response format",
                "Updated GraphQL schema and responses",
                "New Document Service API replaces Entity Service"
            ],
            "configuration": [
                "New server configuration for env variables",
                "Stricter custom configuration requirements"
            ],
            "plugins": [
                "helper-plugin removed",
                "i18n integrated into core"
            ]
        },
        "migration_flags": {
            "rest_api": "Set 'Strapi-Response-Format: v4' header for v4 compatibility",
            "graphql": "Set v4CompatibilityMode: true in graphql.config for v4 compatibility"
        },
        "compatibility_notes": [
            "Uses better-sqlite3 for improved SQLite support",
            "Requires MySQL v8+ for MySQL support",
            "New Document Service API for data operations",
            "Built-in i18n support",
            "New lifecycle hooks system with Document Service Middlewares",
            "Environment variables now handled by server configuration"
        ]
    }
};

// Read config file
const CONFIG_PATH = join(homedir(), '.mcp', 'strapi-mcp-server.config.json');
type ServerConfig = { api_url: string, api_key: string, version?: string };

function loadEnvConfig(): Record<string, ServerConfig> {
    const apiUrl = process.env.STRAPI_API_URL?.trim();
    const apiKey = process.env.STRAPI_API_KEY?.trim();
    const version = process.env.STRAPI_VERSION?.trim();
    const serverName = process.env.STRAPI_SERVER_NAME?.trim() || 'env';

    if (!apiUrl && !apiKey && !version) {
        return {};
    }

    if (!apiUrl || !apiKey) {
        throw new McpError(
            ErrorCode.InvalidParams,
            'Environment configuration is incomplete. STRAPI_API_URL and STRAPI_API_KEY must both be set when using env-based configuration.'
        );
    }

    return {
        [serverName]: {
            api_url: apiUrl,
            api_key: apiKey,
            ...(version ? { version } : {})
        }
    };
}

function loadFileConfig(): Record<string, ServerConfig> {
    try {
        const configContent = readFileSync(CONFIG_PATH, 'utf-8');
        const parsedConfig = JSON.parse(configContent) as Record<string, ServerConfig>;

        if (Object.keys(parsedConfig).length === 0) {
            throw new McpError(ErrorCode.InvalidParams, 'Config file exists but is empty');
        }

        return parsedConfig;
    } catch (error) {
        return {};
    }
}

let config: Record<string, ServerConfig> = {};

try {
    const envConfig = loadEnvConfig();
    const fileConfig = loadFileConfig();

    config = {
        ...fileConfig,
        ...envConfig
    };

    logger.info('Configuration loaded successfully', {
        serverCount: Object.keys(config).length,
        servers: Object.keys(config),
        envServers: Object.keys(envConfig)
    });
} catch (error) {
    logger.error('Error loading server configuration', {
        errorType: error instanceof Error ? error.constructor.name : typeof error
    }, error instanceof Error ? error : undefined);
    config = {};
}

// Create server instance
const server = new Server(
    {
        name: "strapi-mcp",
        version: "2.8.0",
    },
    {
        capabilities: {
            tools: {}
        },
    }
);

// Helper function to get server config
function getServerConfig(serverName: string): { API_URL: string, JWT: string } {
    if (Object.keys(config).length === 0) {
        const exampleConfig = {
            "myserver": {
                "api_url": "http://localhost:1337",
                "api_key": "your-jwt-token-from-strapi-admin"
            }
        };

        throw new McpError(
            ErrorCode.InvalidParams,
            `No server configuration found!\n\n` +
            `Configure a server using one of these options:\n\n` +
            `Option 1: Create a configuration file at:\n` +
            `${CONFIG_PATH}\n\n` +
            `Example configuration:\n` +
            `${JSON.stringify(exampleConfig, null, 2)}\n\n` +
            `File setup steps:\n` +
            `1. Create the .mcp directory: mkdir -p ~/.mcp\n` +
            `2. Create the config file: touch ~/.mcp/strapi-mcp-server.config.json\n` +
            `3. Add your server configuration using the example above\n` +
            `4. Get your JWT token from Strapi Admin Panel > Settings > API Tokens\n` +
            `5. Make sure the file permissions are secure: chmod 600 ~/.mcp/strapi-mcp-server.config.json\n\n` +
            `Option 2: Set environment variables before starting the MCP server:\n` +
            `STRAPI_API_URL=http://localhost:1337\n` +
            `STRAPI_API_KEY=your-jwt-token-from-strapi-admin\n` +
            `STRAPI_VERSION=5.*\n` +
            `STRAPI_SERVER_NAME=env`
        );
    }

    const serverConfig = config[serverName];
    if (!serverConfig) {
        throw new McpError(
            ErrorCode.InvalidParams,
            `Server "${serverName}" not found in config.\n\n` +
            `Available servers: ${Object.keys(config).join(', ')}\n\n` +
            `To add a new server, either edit:\n` +
            `${CONFIG_PATH}\n\n` +
            `Or start the MCP server with:\n` +
            `STRAPI_SERVER_NAME=${serverName}\n` +
            `STRAPI_API_URL=http://localhost:1337\n` +
            `STRAPI_API_KEY=your-jwt-token-from-strapi-admin\n` +
            `STRAPI_VERSION=5.*`
        );
    }
    return {
        API_URL: normalizeApiUrl(serverConfig.api_url),
        JWT: serverConfig.api_key
    };
}

function normalizeApiUrl(apiUrl: string): string {
    return apiUrl.trim().replace(/\/+$/, '');
}

function normalizeEndpoint(endpoint: string): string {
    return endpoint.trim().replace(/^\/+/, '');
}

function buildApiUrl(apiUrl: string, endpoint: string): string {
    const normalizedApiUrl = normalizeApiUrl(apiUrl);
    const normalizedEndpoint = normalizeEndpoint(endpoint);

    return normalizedEndpoint ? `${normalizedApiUrl}/${normalizedEndpoint}` : normalizedApiUrl;
}


// Helper function for making Strapi API requests
async function makeStrapiRequest(
    serverName: string, 
    endpoint: string, 
    params?: Record<string, string>, 
    requestId?: string
): Promise<any> {
    const serverConfig = getServerConfig(serverName);
    let url = buildApiUrl(serverConfig.API_URL, endpoint);
    if (params) {
        const queryString = new URLSearchParams(params).toString();
        url = `${url}?${queryString}`;
    }

    const headers = {
        'Authorization': `Bearer ${serverConfig.JWT}`,
        'Content-Type': 'application/json',
    };

    const startTime = Date.now();
    
    logger.debug(`Making API request to Strapi`, {
        requestId,
        server: serverName,
        endpoint,
        method: 'GET',
        hasParams: !!params,
        url: url.replace(serverConfig.JWT, '[REDACTED]')
    });

    try {
        const response = await fetch(url, { headers });
        const duration = Date.now() - startTime;
        
        logger.logApiCall(
            requestId || 'unknown',
            'GET',
            endpoint,
            duration,
            response.status,
            serverName
        );
        
        return await handleStrapiError(response, `Request to ${endpoint}`, requestId);
    } catch (error) {
        const duration = Date.now() - startTime;
        
        logger.error("Error making Strapi request", {
            requestId,
            server: serverName,
            endpoint,
            method: 'GET',
            duration,
            errorType: error instanceof Error ? error.constructor.name : typeof error
        }, error instanceof Error ? error : undefined);
        
        throw error;
    }
}

// Helper function to infer content type for uploads
function inferContentType(fileName: string, format: string): string {
    if (format !== 'original') {
        return `image/${format}`;
    }

    const extension = extname(fileName).toLowerCase();
    const contentTypeMap: Record<string, string> = {
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.png': 'image/png',
        '.webp': 'image/webp',
        '.gif': 'image/gif',
        '.svg': 'image/svg+xml',
        '.avif': 'image/avif',
        '.pdf': 'application/pdf',
        '.mp4': 'video/mp4',
        '.webm': 'video/webm',
        '.mp3': 'audio/mpeg',
        '.wav': 'audio/wav'
    };

    return contentTypeMap[extension] ?? 'application/octet-stream';
}

// Helper function to extract filename from URL
function extractFileNameFromUrl(url: string): string {
    try {
        const parsedUrl = new URL(url);
        const candidate = basename(parsedUrl.pathname);
        return candidate ? decodeURIComponent(candidate) : 'media';
    } catch {
        const fallback = url.split('/').pop();
        return fallback && fallback.length > 0 ? fallback : 'media';
    }
}

// Helper function to extract filename from local path
function extractFileNameFromLocalPath(localPath: string): string {
    const candidate = basename(localPath);
    return candidate.length > 0 ? candidate : 'media';
}

// Helper function to download media from URL
async function downloadMedia(url: string): Promise<Buffer> {
    const response = await fetch(url);
    if (!response.ok) {
        throw new McpError(ErrorCode.InternalError, `Failed to download media: ${response.statusText}`);
    }
    return Buffer.from(await response.arrayBuffer());
}

// Helper function to read local media file
async function readLocalMedia(localPath: string): Promise<Buffer> {
    try {
        const fileStat = await stat(localPath);
        if (!fileStat.isFile()) {
            throw new McpError(ErrorCode.InvalidParams, `localPath must point to a file: ${localPath}`);
        }
    } catch (error) {
        if (error instanceof McpError) {
            throw error;
        }

        throw new McpError(
            ErrorCode.InvalidParams,
            `Failed to access local media path: ${localPath}`
        );
    }

    try {
        return await readFile(localPath);
    } catch {
        throw new McpError(
            ErrorCode.InternalError,
            `Failed to read local media file: ${localPath}`
        );
    }
}

// Helper function to process image with Sharp
async function processImage(buffer: Buffer, format: string, quality: number): Promise<Buffer> {
    if (format === 'original') {
        return buffer;
    }

    let sharpInstance = sharp(buffer);

    switch (format) {
        case 'jpeg':
            sharpInstance = sharpInstance.jpeg({ quality });
            break;
        case 'png':
            // PNG quality is 0-100 for zlib compression level
            sharpInstance = sharpInstance.png({
                compressionLevel: Math.floor((100 - quality) / 100 * 9)
            });
            break;
        case 'webp':
            sharpInstance = sharpInstance.webp({ quality });
            break;
    }

    return sharpInstance.toBuffer();
}

// Update uploadMedia with server config and authorization check
async function uploadMedia(serverName: string, mediaBuffer: Buffer, fileName: string, format: string, metadata?: Record<string, any>, userAuthorized: boolean = false, requestId?: string): Promise<any> {
    // Check for explicit user authorization for this upload operation
    if (!userAuthorized) {
        throw new McpError(
            ErrorCode.InvalidParams,
            `AUTHORIZATION REQUIRED: Media upload operations require explicit user authorization.\n\n` +
            `IMPORTANT: The client MUST:\n` +
            `1. Ask the user for explicit permission before uploading this media\n` +
            `2. Show the user what media will be uploaded\n` +
            `3. Receive clear confirmation from the user\n` +
            `4. Set userAuthorized=true when making the request\n\n` +
            `This is a security measure to prevent unauthorized uploads.`
        );
    }

    const serverConfig = getServerConfig(serverName);
    const formData = new FormData();

    // Update filename extension if format is changed
    if (format !== 'original') {
        fileName = fileName.replace(/\.[^/.]+$/, '') + '.' + format;
    }

    // Add the file
    formData.append('files', mediaBuffer, {
        filename: fileName,
        contentType: inferContentType(fileName, format)
    });

    // Add metadata if provided
    if (metadata) {
        formData.append('fileInfo', JSON.stringify(metadata));
    }

    const url = buildApiUrl(serverConfig.API_URL, 'api/upload');
    const startTime = Date.now();
    
    logger.debug(`Uploading media to Strapi`, {
        requestId,
        server: serverName,
        fileName,
        format,
        hasMetadata: !!metadata,
        bufferSize: mediaBuffer.length,
        userAuthorized
    });
    
    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${serverConfig.JWT}`,
            ...formData.getHeaders()
        },
        body: formData
    });

    const duration = Date.now() - startTime;
    
    logger.logApiCall(
        requestId || 'unknown',
        'POST',
        '/api/upload',
        duration,
        response.status,
        serverName
    );

    return handleStrapiError(response, 'Media upload', requestId);
}

// List available tools 
server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
        tools: [
            {
                name: "strapi_list_servers",
                description: `List all available Strapi servers from the configuration.

## Security Policy
STRICT_USER_AUTHORIZATION_REQUIRED: No write operations without explicit user authorization.
Protected operations: POST (Create), PUT (Update), DELETE (Delete), Media Upload.
All write operations require userAuthorized: true parameter.

## Configuration Resolution
- Config file path: ~/.mcp/strapi-mcp-server.config.json
- File-based and env-based server definitions are merged at startup
- If the same server name exists in both places, env values override file values

## Strapi Version Support
Supports both Strapi v4 and v5 with automatic version detection.

### Version Differences
- v4: Numeric IDs, nested attributes under 'attributes', data wrapper in responses
- v5: Document-based IDs (documentId), flat structure, direct attribute access

### Common Errors
- 404: Using numeric ID instead of documentId, wrong plural/singular form
- 405: Incorrect endpoint (/article instead of /articles)
- 400: Missing data wrapper in request body

### Best Practices
1. Call strapi_get_content_types only when the user explicitly asks for schema/components info, or when the content structure/endpoints are unknown
2. Use documentId (not numeric id) for Strapi v5
3. Always use data wrapper for updates: { data: { field: value } }
4. Use pluralName for collection endpoints (api/articles)
5. Validate URLs with webtools before using them`,
                inputSchema: zodToJsonSchema(ToolSchemas.strapi_list_servers),
            },
            {
                name: "strapi_get_content_types",
                description: `Get all content types from Strapi. Returns the complete schema of all content types.

## Use This Tool Only When Needed
Call this tool only when the user explicitly asks for content type schema, or when endpoint names, fields, relations, or required validations are unknown.

Typical reasons to call it:
1. Confirm pluralName or singularName before building an endpoint
2. Inspect available fields and required validations
3. Check relation or component structure before writing new data

## Schema Conventions
- singularName: Used for single item queries (e.g., "article")
- pluralName: Used for collection endpoints (e.g., "articles")
- collectionName: Database collection name

## Endpoint Patterns
- Collection: GET /api/{pluralName}
- Single: GET /api/{pluralName}/{id}
- Create: POST /api/{pluralName}
- Update: PUT /api/{pluralName}/{id}
- Delete: DELETE /api/{pluralName}/{id}`,
                inputSchema: {
                    ...zodToJsonSchema(ToolSchemas.strapi_get_content_types),
                    properties: {
                        ...zodToJsonSchema(ToolSchemas.strapi_get_content_types).properties,
                        server: {
                            ...zodToJsonSchema(ToolSchemas.strapi_get_content_types).properties.server,
                            description: "The name of the server to connect to"
                        }
                    }
                },
            },
            {
                name: "strapi_get_components",
                description: "Get all components from Strapi with pagination support. Returns both component data and pagination metadata (page, pageSize, total, pageCount). Call this tool only when the user explicitly asks for component schema/details, or when component structure is unknown.",
                inputSchema: {
                    ...zodToJsonSchema(ToolSchemas.strapi_get_components),
                    properties: {
                        ...zodToJsonSchema(ToolSchemas.strapi_get_components).properties,
                        server: {
                            ...zodToJsonSchema(ToolSchemas.strapi_get_components).properties.server,
                            description: "The name of the server to connect to"
                        },
                        page: {
                            ...zodToJsonSchema(ToolSchemas.strapi_get_components).properties.page,
                            description: "Page number (starts at 1)",
                            default: 1
                        },
                        pageSize: {
                            ...zodToJsonSchema(ToolSchemas.strapi_get_components).properties.pageSize,
                            description: "Number of items per page",
                            default: 25
                        }
                    }
                },
            },
            {
                name: "strapi_rest",
                description: `Execute REST API requests against Strapi endpoints. IMPORTANT: All write operations (POST, PUT, DELETE) require explicit user authorization via the userAuthorized parameter.

## Endpoint Rules
- endpoint is path-only, for example: api/articles
- NEVER put query strings in endpoint
- ALWAYS pass filters, pagination, sorting, populate, and status=draft via params

Bad:
{
    endpoint: 'api/articles?filters[slug][$eq]=example'
}

Good:
{
    endpoint: 'api/articles',
    params: {
        filters: {
            slug: {
                $eq: 'example'
            }
        }
    }
}

## Reading Data
params: { populate: ['SEO'] } // Populate a component
params: { populate: { SEO: { fields: ['Title', 'seoDescription'] } } } // With field selection
params: { filters: { title: { $contains: 'search' } } } // Filter results
params: { sort: ['createdAt:desc'] } // Sort results
params: { pagination: { page: 1, pageSize: 10 } } // Pagination

## Writing Data (REQUIRES userAuthorized: true)
body: {
  data: {
    componentName: { Title: 'value' }, // Single component
    componentName: [{ field: 'value' }] // Repeatable component
  }
}

## Request Body Input Rules (CRITICAL)
- body accepts only:
    - a JSON object (recommended)
    - a JSON string that parses to an object
- body does NOT accept file path pointers such as '@/tmp/payload.json' or './payload.json'
- If body data is stored in a file, read the file content first and pass parsed JSON

Invalid body example:
{
        body: '@/tmp/payload.json'
}

Valid body example (object):
{
        body: {
                data: {
                        title: 'Example Title'
                }
        }
}

Valid body example (JSON string):
{
        body: '{"data":{"title":"Example Title"}}'
}

Write example:
{
    method: 'POST',
    endpoint: 'api/articles',
    body: {
        data: {
            title: 'New Article'
        }
    },
    userAuthorized: true
}

                                ## Draft Pattern
                                                                Create draft entities by passing status=draft in params.

                                                                Example:
                                                                {
                                                                    method: 'POST',
                                                                    endpoint: 'api/tags',
                                                                    params: {
                                                                        status: 'draft'
                                                                    },
                                                                    body: {
                                                                        data: {
                                                                            name: 'Wallet Security'
                                                                        }
                                                                    },
                                                                    userAuthorized: true
                                                                }

## Multiple Record Writes
strapi_rest sends one HTTP request at a time. For multiple records, send one POST per record.

## Debugging Guide
- 404 Error: Check plural/singular form, use documentId not numeric id
- 400 Error: Check if data wrapper is present in body
- 405 Error: Check endpoint format (/articles not /article)
- URL Errors: Validate URLs with webtools first
- ID Problems: Use documentId for Strapi v5

## Strapi v5 Specifics
- Use documentId instead of numeric id
- Direct attribute access (no nested attributes)
- No data wrapper in GET responses`,
                inputSchema: {
                    ...zodToJsonSchema(ToolSchemas.strapi_rest),
                    properties: {
                        ...zodToJsonSchema(ToolSchemas.strapi_rest).properties,
                        server: {
                            ...zodToJsonSchema(ToolSchemas.strapi_rest).properties.server,
                            description: "The name of the server to connect to"
                        },
                        endpoint: {
                            ...zodToJsonSchema(ToolSchemas.strapi_rest).properties.endpoint,
                            description: "The API endpoint path only (e.g., 'api/articles'). NEVER include query strings here. Pass filters, pagination, sorting, populate, and draft status via params."
                        },
                        method: {
                            ...zodToJsonSchema(ToolSchemas.strapi_rest).properties.method,
                            description: "HTTP method to use",
                            default: "GET"
                        },
                        params: {
                            ...zodToJsonSchema(ToolSchemas.strapi_rest).properties.params,
                            description: "Query parameters appended to the request URL. Use this field for filters, pagination, sorting, populate, and draft creation. Example: params: { filters: { slug: { $eq: 'example' } }, pagination: { pageSize: 100 } }. For draft entity creation, use params: { status: 'draft' }."
                        },
                        body: {
                            ...zodToJsonSchema(ToolSchemas.strapi_rest).properties.body,
                            description: "Request body for POST/PUT requests. Accepted types: (1) object, or (2) JSON string that parses to an object. Not supported: file-path pointers such as '@/tmp/payload.json'. If body data is in a file, read the file content and pass parsed JSON. For components, use: { data: { componentName: { field: 'value' } } } for single components or { data: { componentName: [{ field: 'value' }] } } for repeatable components."
                        },
                        userAuthorized: {
                            ...zodToJsonSchema(ToolSchemas.strapi_rest).properties.userAuthorized,
                            description: "REQUIRED for POST/PUT/DELETE operations. Client MUST obtain explicit user authorization before setting this to true.",
                            default: false
                        }
                    }
                },
            },
            {
                name: "strapi_upload_media",
                                description: `Upload media to Strapi's media library from either a remote URL or a local file path, with optional format conversion, quality control, and metadata options. IMPORTANT: This is a write operation that REQUIRES explicit user authorization via the userAuthorized parameter.

## Parameter Rules
- server: Required. Must match a configured server name.
- source: Provide exactly one of url or localPath.
- url: HTTP/HTTPS remote media source.
- localPath: Existing readable file path on the MCP server host machine.
- format: jpeg | png | webp | original.
- quality: 1-100, used only when format is not original.
- metadata: Optional Strapi fileInfo fields (name, caption, alternativeText, description).
- userAuthorized: Must be true for this write operation.

## Source Selection
- Use url when media is already hosted remotely.
- Use localPath when media exists on local disk.
- Do not pass both fields, and do not omit both fields.

## Upload Steps
1. Upload via strapi_upload_media using exactly one source: url or localPath
2. Get image ID from response
3. Link to content using strapi_rest PUT request

## Input Examples
Upload from local file:
{
    "server": "product",
    "localPath": "/Users/you/assets/cover.svg",
    "format": "original",
    "metadata": {
        "name": "cover.svg",
        "alternativeText": "Wallet security cover image"
    },
    "userAuthorized": true
}

Upload from URL:
{
    "server": "product",
    "url": "https://example.com/image.png",
    "format": "webp",
    "quality": 85,
    "userAuthorized": true
}

## Linking Images to Content (Strapi v5)
After upload, use PUT request to link:
{
  "method": "PUT",
  "endpoint": "api/articles/{documentId}",
  "body": { "data": { "images": ["imageId"] } },
  "userAuthorized": true
}`,
                inputSchema: {
                    ...zodToJsonSchema(ToolSchemas.strapi_upload_media),
                    oneOf: [
                        {
                            required: ["url"],
                            not: { required: ["localPath"] }
                        },
                        {
                            required: ["localPath"],
                            not: { required: ["url"] }
                        }
                    ],
                    properties: {
                        ...zodToJsonSchema(ToolSchemas.strapi_upload_media).properties,
                        server: {
                            ...zodToJsonSchema(ToolSchemas.strapi_upload_media).properties.server,
                            description: "Required. Name of the target server from your MCP config (for example: 'product')."
                        },
                        url: {
                            ...zodToJsonSchema(ToolSchemas.strapi_upload_media).properties.url,
                            description: "Optional remote source URL (http/https). Mutually exclusive with localPath. The file name is inferred from the URL path when possible."
                        },
                        localPath: {
                            ...zodToJsonSchema(ToolSchemas.strapi_upload_media).properties.localPath,
                            description: "Optional local filesystem path to upload from disk. Mutually exclusive with url. Must point to an existing readable file on the MCP host machine."
                        },
                        format: {
                            ...zodToJsonSchema(ToolSchemas.strapi_upload_media).properties.format,
                            description: "Output format. Use 'original' to keep source bytes unchanged, or jpeg/png/webp to convert with Sharp before upload.",
                            default: "original"
                        },
                        quality: {
                            ...zodToJsonSchema(ToolSchemas.strapi_upload_media).properties.quality,
                            description: "Quality level from 1 to 100. Applies only when format is jpeg/png/webp; ignored when format is original.",
                            default: 80
                        },
                        metadata: {
                            type: "object",
                            properties: {
                                name: {
                                    type: "string",
                                    description: "Optional display name shown in Strapi media library."
                                },
                                caption: {
                                    type: "string",
                                    description: "Optional caption text stored with the media entry."
                                },
                                alternativeText: {
                                    type: "string",
                                    description: "Optional alt text for accessibility and SEO."
                                },
                                description: {
                                    type: "string",
                                    description: "Optional detailed description field in Strapi media metadata."
                                }
                            },
                            additionalProperties: false
                        },
                        userAuthorized: {
                            ...zodToJsonSchema(ToolSchemas.strapi_upload_media).properties.userAuthorized,
                            description: "Required for upload. Must be true after explicit user confirmation; false will be rejected by validation/security checks.",
                            default: false
                        }
                    }
                }
            }
        ],
    };
});

// Handle tool execution
server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const requestId = logger.generateRequestId();
    const startTime = Date.now();
    
    logger.startRequest(requestId, name);
    
    let success = false;
    let result: any;
    
    try {
        if (name === "strapi_list_servers") {
            // Validate input using Zod (no args for this tool)
            validateToolInput("strapi_list_servers", args, requestId);
            if (Object.keys(config).length === 0) {
                const exampleConfig = {
                    "myserver": {
                        "api_url": "http://localhost:1337",
                        "api_key": "your-jwt-token-from-strapi-admin",
                        "version": "5.*"
                    }
                };

                result = {
                    content: [
                        {
                            type: "text",
                            text: JSON.stringify({
                                error: "No servers configured",
                                help: {
                                    message: "No server configuration found. Please create a configuration file.",
                                    config_path: CONFIG_PATH,
                                    example_config: exampleConfig,
                                    setup_steps: [
                                        "Create the .mcp directory: mkdir -p ~/.mcp",
                                        "Create the config file: touch ~/.mcp/strapi-mcp-server.config.json",
                                        "Add your server configuration using the example above",
                                        "Get your JWT token from Strapi Admin Panel > Settings > API Tokens",
                                        "Make sure the file permissions are secure: chmod 600 ~/.mcp/strapi-mcp-server.config.json"
                                    ]
                                }
                            }, null, 2),
                        },
                    ],
                };
            }

            const servers = Object.keys(config).map(serverName => {
                const serverConfig = config[serverName];
                const version = serverConfig.version || "v4"; // Default to v4 if not specified

                // Extract major version from different formats: "5.*", "4.1.5", "v4", "4.*"
                let majorVersion: keyof StrapiVersionDifferences;
                if (version.includes('*')) {
                    // Handle "5.*" or "4.*" format
                    majorVersion = version.split('.')[0] as keyof StrapiVersionDifferences;
                } else if (version.startsWith('v')) {
                    // Handle "v4" or "v5" format
                    majorVersion = version.substring(1) as keyof StrapiVersionDifferences;
                } else {
                    // Handle "4.1.5" or plain "4" format
                    majorVersion = version.split('.')[0] as keyof StrapiVersionDifferences;
                }

                return {
                    name: serverName,
                    api_url: serverConfig.api_url,
                    version: serverConfig.version,
                    version_details: STRAPI_VERSION_DIFFERENCES[majorVersion]
                };
            });

            result = {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify({
                            servers,
                            version_differences: STRAPI_VERSION_DIFFERENCES,
                            user_action_required: {
                                message: "Please specify which server you want to work with by providing the server name in your next command.",
                                example: "For example: 'I want to work with the server \"myserver\"' or 'Use server \"myserver\" for the next operations'",
                                available_servers: servers.map(s => s.name),
                                warning: "Only use servers that are listed in available_servers. Do not attempt to access servers that are not properly configured."
                            },
                            security: {
                                note: "For security reasons, only servers listed in the configuration file can be accessed.",
                                requirement: "Each server must be properly configured with valid credentials before use."
                            }
                        }, null, 2),
                    },
                ],
            };
        } else if (name === "strapi_get_content_types") {
            // Validate input using Zod
            const validatedArgs = validateToolInput("strapi_get_content_types", args, requestId);
            const { server } = validatedArgs;
            logger.startRequest(requestId, name, server);
            const data = await makeStrapiRequest(server, "/api/content-type-builder/content-types", undefined, requestId);

            // Add helpful usage information to the response
            const response = {
                data: data,
                usage_guide: {
                    naming_conventions: {
                        rest_api: "Use pluralName for REST API endpoints (e.g., 'api/articles' for pluralName: 'articles')",
                        graphql: {
                            collections: "Use pluralName for collections (e.g., 'query { articles { data { id } } }')",
                            single_items: "Use singularName for single items (e.g., 'query { article(id: 1) { data { id } } }')"
                        }
                    },
                    examples: {
                        rest: {
                            collection: "GET /api/{pluralName}",
                            single: "GET /api/{pluralName}/{id}",
                            create: "POST /api/{pluralName}",
                            update: "PUT /api/{pluralName}/{id}",
                            delete: "DELETE /api/{pluralName}/{id}"
                        },
                        graphql: {
                            collection: "query { pluralName(pagination: { page: 1, pageSize: 100 }) { data { id attributes } } }",
                            single: "query { singularName(id: 1) { data { id attributes } } }",
                            create: "mutation { createPluralName(data: { field: value }) { data { id } } }",
                            update: "mutation { updatePluralName(id: 1, data: { field: value }) { data { id } } }"
                        }
                    },
                    important_notes: [
                        "Always check singularName and pluralName in the schema for correct endpoint/query names",
                        "REST endpoints always start with 'api/'",
                        "Include pagination in GraphQL collection queries",
                        "For updates, always fetch current data first and include ALL fields in the update"
                    ]
                }
            };

            result = {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify(response, null, 2),
                    },
                ],
            };
        } else if (name === "strapi_get_components") {
            // Validate input using Zod (with defaults applied)
            const validatedArgs = validateToolInput("strapi_get_components", args, requestId);
            const { server, page, pageSize } = validatedArgs;
            logger.startRequest(requestId, name, server);
            const params = {
                'pagination[page]': page.toString(),
                'pagination[pageSize]': pageSize.toString(),
            };

            const data = await makeStrapiRequest(server, "/api/content-type-builder/components", params, requestId);

            // Add pagination metadata to the response
            const response = {
                data: data,
                pagination: {
                    page,
                    pageSize,
                    total: data.length,
                    pageCount: Math.ceil(data.length / pageSize),
                },
            };

            result = {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify(response, null, 2),
                    },
                ],
            };
        } else if (name === "strapi_rest") {
            // Validate input using Zod (includes authorization check)
            const validatedArgs = validateToolInput("strapi_rest", args, requestId);
            const { server, endpoint, method, params, body, userAuthorized } = validatedArgs;
            logger.startRequest(requestId, name, server);

            const data = await makeRestRequest(server, endpoint, method, params, body, userAuthorized, requestId);
            result = {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify(data, null, 2),
                    },
                ],
            };
        } else if (name === "strapi_upload_media") {
            // Validate input using Zod (includes authorization check)
            const validatedArgs = validateToolInput("strapi_upload_media", args, requestId);
            const { server, url, localPath, format, quality, metadata, userAuthorized } = validatedArgs;
            logger.startRequest(requestId, name, server);

            let fileName: string;
            let mediaBuffer: Buffer;

            if (url) {
                fileName = extractFileNameFromUrl(url);
                mediaBuffer = await downloadMedia(url);
            } else if (localPath) {
                fileName = extractFileNameFromLocalPath(localPath);
                mediaBuffer = await readLocalMedia(localPath);
            } else {
                throw new McpError(
                    ErrorCode.InvalidParams,
                    "Provide exactly one source: either url or localPath"
                );
            }

            // Process the image if format conversion is requested
            const processedBuffer = await processImage(mediaBuffer, format, quality);

            // Upload to Strapi with metadata (with authorization check)
            const data = await uploadMedia(server, processedBuffer, fileName, format, metadata, userAuthorized, requestId);

            // Format response with helpful usage information
            const response = {
                success: true,
                data: data,
                image_info: {
                    format: format === 'original' ? 'original (unchanged)' : format,
                    quality: format === 'original' ? 'original (unchanged)' : quality,
                    filename: data[0].name,
                    size: data[0].size,
                    mime: data[0].mime
                },
                usage_guide: {
                    file_id: data[0].id,
                    url: data[0].url,
                    how_to_use: {
                        rest_api: "Use the file ID in your content type's media field",
                        graphql: "Use the file ID in your GraphQL mutations",
                        examples: {
                            rest: "PUT /api/content-type/1 with body: { data: { image: " + data[0].id + " } }",
                            graphql: "mutation { updateContentType(id: 1, data: { image: " + data[0].id + " }) { data { id } } }"
                        }
                    }
                }
            };

            result = {
                content: [
                    {
                        type: "text",
                        text: JSON.stringify(response, null, 2)
                    }
                ]
            };
        } else {
            throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
        }
        
        success = true;
        return result;
    } catch (error: unknown) {
        const duration = Date.now() - startTime;
        logger.endRequest(requestId, false, error instanceof Error ? error : undefined);
        logger.logToolExecution(name, args, requestId, duration, false, error instanceof Error ? error : undefined);
        
        const errorMessage = error instanceof Error ? error.message : 'An unknown error occurred';
        return {
            content: [
                {
                    type: "text",
                    text: `Error: ${errorMessage}`,
                },
            ],
        };
    } finally {
        if (success) {
            const duration = Date.now() - startTime;
            logger.endRequest(requestId, true);
            logger.logToolExecution(name, args, requestId, duration, true);
        }
    }
});

// Enhanced REST request function
async function makeRestRequest(
    serverName: string,
    endpoint: string,
    method: string = 'GET',
    params?: Record<string, any>,
    body?: Record<string, any>,
    userAuthorized: boolean = false,
    requestId?: string
): Promise<any> {
    // Check for write operations that require explicit user authorization
    if ((method === 'POST' || method === 'PUT' || method === 'DELETE') && !userAuthorized) {
        throw new McpError(
            ErrorCode.InvalidParams,
            `AUTHORIZATION REQUIRED: ${method} operations require explicit user authorization.\n\n` +
            `IMPORTANT: The client MUST:\n` +
            `1. Ask the user for explicit permission before making this request\n` +
            `2. Show the user exactly what data will be modified\n` +
            `3. Receive clear confirmation from the user\n` +
            `4. Set userAuthorized=true when making the request\n\n` +
            `This is a security measure to prevent unauthorized data modifications.`
        );
    }

    if (endpoint.includes('?')) {
        throw new McpError(
            ErrorCode.InvalidParams,
            "Endpoint must not include query strings. Pass query parameters via params."
        );
    }

    const serverConfig = getServerConfig(serverName);
    let url = buildApiUrl(serverConfig.API_URL, endpoint);

    // Parse query parameters if provided
    if (params) {
        const queryString = qs.stringify(params, {
            encodeValuesOnly: true
        });
        if (queryString) {
            url = `${url}?${queryString}`;
        }
    }

    const headers = {
        'Authorization': `Bearer ${serverConfig.JWT}`,
        'Content-Type': 'application/json',
    };

    const requestOptions: RequestInit = {
        method,
        headers,
    };

    if (body && (method === 'POST' || method === 'PUT')) {
        requestOptions.body = JSON.stringify(body);
    }

    const startTime = Date.now();
    
    logger.debug(`Making REST request to Strapi`, {
        requestId,
        server: serverName,
        endpoint,
        method,
        hasParams: !!params,
        hasBody: !!body,
        userAuthorized,
        url: url.replace(serverConfig.JWT, '[REDACTED]')
    });

    try {
        const response = await fetch(url, requestOptions);
        const duration = Date.now() - startTime;
        
        logger.logApiCall(
            requestId || 'unknown',
            method,
            endpoint,
            duration,
            response.status,
            serverName
        );
        
        return await handleStrapiError(response, `REST request to ${endpoint}`, requestId);
    } catch (error) {
        const duration = Date.now() - startTime;
        
        logger.error(`REST request to ${endpoint} failed`, {
            requestId,
            server: serverName,
            endpoint,
            method,
            duration,
            errorType: error instanceof Error ? error.constructor.name : typeof error
        }, error instanceof Error ? error : undefined);
        
        throw error;
    }
}

// Update error handler to be more generic and helpful
async function handleStrapiError(response: Response, context: string, requestId?: string): Promise<any> {
    if (!response.ok) {
        let errorMessage = `${context} failed with status: ${response.status}`;
        let errorData: any = null;
        
        try {
            errorData = await response.json() as any;
            if (errorData && typeof errorData === 'object' && 'error' in errorData) {
                errorMessage += ` - ${errorData.error?.message || JSON.stringify(errorData.error)}`;

                // Add helpful hints based on status
                if (response.status === 400) {
                    errorMessage += "\nHINT: Check the request structure matches Strapi's expectations. For v4/v5 differences, refer to Strapi's migration guide.";
                } else if (response.status === 404) {
                    errorMessage += "\nHINT: Check the endpoint path and ID are correct.";
                }
            }
        } catch {
            errorMessage += ` - ${response.statusText}`;
        }
        
        logger.error(`Strapi API error: ${context}`, {
            requestId,
            status: response.status,
            statusText: response.statusText,
            url: response.url,
            errorData: errorData,
            context
        });
        
        throw new McpError(ErrorCode.InternalError, errorMessage);
    }
    
    logger.debug(`Strapi API success: ${context}`, {
        requestId,
        status: response.status,
        url: response.url
    });
    
    return response.json();
}

// Start the server
async function main() {
    try {
        logger.info("Starting Strapi MCP Server", {
            version: "2.8.0",
            configuredServers: Object.keys(config).length,
            logLevel: LogLevel[logger.getConfig().level]
        });
        
        const transport = new StdioServerTransport();
        await server.connect(transport);
        
        logger.info("Strapi MCP Server started successfully", {
            transport: "stdio",
            hasCapabilities: true
        });
        
        // Use stderr for compatibility message (not stdout which interferes with MCP protocol)
        process.stderr.write("Strapi MCP Server running on stdio\n");
    } catch (error) {
        logger.error("Failed to start Strapi MCP Server", {
            errorType: error instanceof Error ? error.constructor.name : typeof error
        }, error instanceof Error ? error : undefined);
        throw error;
    }
}

main().catch((error: unknown) => {
    logger.error("Fatal error in main()", {
        errorType: error instanceof Error ? error.constructor.name : typeof error
    }, error instanceof Error ? error : undefined);
    process.exit(1);
}); 