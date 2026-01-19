import express from "express";
import { Submission } from "../models/Submission.js";

const router = express.Router();

router.post("/", async (req, res) => {
  const id = await Submission.create(req.body);
  res.status(201).json({ id });
});

router.get("/:applicationId", async (req, res) => {
  const subs = await Submission.getByApplication(req.params.applicationId);
  res.json(subs);
});

export default router;
