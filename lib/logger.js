// Centralized logger using winston for best practices
const { createLogger, format, transports } = require('winston');
const { combine, timestamp, printf, errors, colorize } = format;

// Custom format to sanitize log messages (removes newlines, tabs, etc.)
const sanitize = format((info) => {
    if (typeof info.message === 'string') {
        info.message = info.message.replace(/[\r\n\t]+/g, ' ');
    }
    return info;
});

const logFormat = printf(({ level, message, timestamp, stack }) => {
    return `${timestamp} [${level}]: ${stack || message}`;
});

const logger = createLogger({
    level: 'info',
    format: combine(
        sanitize(),
        errors({ stack: true }),
        timestamp(),
        logFormat
    ),
    transports: [
        new transports.Console({ format: combine(colorize(), logFormat) }),
        new transports.File({ filename: 'app.log' })
    ]
});

module.exports = logger;
