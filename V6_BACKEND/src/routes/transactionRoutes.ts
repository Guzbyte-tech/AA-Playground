import { Transaction } from "ethers";
import {
  Router,
  Request,
  Response,
  NextFunction,
  RequestHandler,
  ErrorRequestHandler,
} from "express";
import { TransactionController } from "../controllers/TransactionController";
import { authMiddleware } from "../middlewares/auth.middleware";

const transactionController = new TransactionController();
const router = Router();

router.post("/build", authMiddleware, transactionController.buildUserOp);
router.post("/submit", authMiddleware, transactionController.submitTransaction);
router.post("/status", authMiddleware, transactionController.getTransactionStatus);


export default router;