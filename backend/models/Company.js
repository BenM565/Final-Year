import { db } from "../config/db.js";

export const Company = {
  async getById(id) {
    const [rows] = await db.query(
      "SELECT * FROM companies WHERE id = ?",
      [id]
    );
    return rows[0];
  }
};
