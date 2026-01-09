const sql = require('mssql');

const config = {
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    server: process.env.DB_SERVER, 
    database: process.env.DB_NAME,
    options: {
        encrypt: true, // Required for Azure
        trustServerCertificate: false,
        connectTimeout: 60000, // Wait 60s for Serverless DB to wake up
        requestTimeout: 60000  // Wait 60s for complex queries
    }
};

async function getConnection() {
    try {
        const pool = await sql.connect(config);
        return pool;
    } catch (err) {
        console.error('SQL Connection Error', err);
        throw err;
    }
}

module.exports = { getConnection, sql };
