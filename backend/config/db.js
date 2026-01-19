import mysql from "mysql2/promise";

export const db = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "YOUR_PASSWORD",
  database: "YOUR_DATABASE",
  waitForConnections: true,
  connectionLimit: 10
});
