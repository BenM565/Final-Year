import { db } from "../config/db.js";

export const Task = {
  async getAll() {
    const [rows] = await db.query("SELECT * FROM tasks");
    return rows;
  },

  async create(data) {
    const [result] = await db.query(
      "INSERT INTO tasks (title, description, company_id) VALUES (?, ?, ?)",
      [data.title, data.description, data.company_id]
    );
    return result.insertId;
  }
};
