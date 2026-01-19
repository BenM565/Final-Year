import express from "express";
import { Application } from "../models/Application.js";

const router = express.Router();

router.post("/", async (req, res) => {
  const { studentId, taskId } = req.body;
  const id = await Application.create(studentId, taskId);
  res.status(201).json({ id });
});

router.get("/student/:id", async (req, res) => {
  const apps = await Application.getByStudent(req.params.id);
  res.json(apps);
});

export default router;
