import express from "express";
import "./config/db.js";

import taskRoutes from "./routes/tasks.js";
import applicationRoutes from "./routes/applications.js";
import submissionRoutes from "./routes/submission.js";

const app = express();

app.use(express.json());

app.use("/tasks", taskRoutes);
app.use("/applications", applicationRoutes);
app.use("/submissions", submissionRoutes);

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
s