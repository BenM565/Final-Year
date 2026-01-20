import { db } from "../config/db.js";

export const Application = {
  async create(studentId, taskId) {
    const [result] = await db.query(
      "INSERT INTO applications (student_id, task_id, status) VALUES (?, ?, 'pending')",
      [studentId, taskId]
    );
    return result.insertId;
  },

  async getByStudent(studentId) {
    const [rows] = await db.query(
      "SELECT * FROM applications WHERE student_id = ?",
      [studentId]
    );
    return rows;
  }
};
