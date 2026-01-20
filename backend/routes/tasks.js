import express from "express";
import { Task } from "../models/Task.js";

const router = express.Router();

router.get("/", async (req, res) => {
  const tasks = await Task.getAll();
  res.json(tasks);
});

router.post("/", async (req, res) => {
  const id = await Task.create(req.body);
  res.status(201).json({ id });
});

export default router;
