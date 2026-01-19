import { db } from "../config/db.js";

export const Student = {
  async getById(id) {
    const [rows] = await db.query(
      "SELECT * FROM students WHERE id = ?",
      [id]
    );
    return rows[0];
  },

  async create(data) {
    const [result] = await db.query(
      "INSERT INTO students (name, email) VALUES (?, ?)",
      [data.name, data.email]
    );
    return result.insertId;
  }
};
