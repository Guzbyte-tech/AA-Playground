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

const transactionController = new TransactionController();
const router = Router();

router.post("/build", transactionController.buildUserOp);
router.post("/submit", transactionController.submitTransaction);
router.post("/status", transactionController.getTransactionStatus);


export default router;