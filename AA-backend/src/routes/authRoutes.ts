import {
  Router,
  Request,
  Response,
  NextFunction,
  RequestHandler,
  ErrorRequestHandler,
} from "express";
import { AuthController } from "../controllers/AuthController";

const authController = new AuthController();
const router = Router();

router.post("/register", authController.register);
router.post("/login", authController.login);


export default router;