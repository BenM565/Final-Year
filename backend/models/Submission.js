import { db } from "../config/db.js";

export const Submission = {
  async create(data) {
    const [result] = await db.query(
      "INSERT INTO submissions (application_id, content) VALUES (?, ?)",
      [data.application_id, data.content]
    );
    return result.insertId;
  },

  async getByApplication(applicationId) {
    const [rows] = await db.query(
      "SELECT * FROM submissions WHERE application_id = ?",
      [applicationId]
    );
    return rows;
  }
};
