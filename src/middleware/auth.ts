import { Response, NextFunction } from "express";
import HttpStatusCodes from "http-status-codes";
import jwt from "jsonwebtoken";
import Payload from "../types/Payload";
import Request from "../types/Request";
import { JWT_SECRET } from '../../src/types/secrets';


export default function(req: Request, res: Response, next: NextFunction) {
  // Get token from header
  const token = req.header("x-auth-token");

  // Check if no token
  if (!token) {
    return res
      .status(HttpStatusCodes.UNAUTHORIZED)
      .json({ msg: "No token, authorization denied" });
  }
  // Verify token
  try {
    const payload: Payload | any = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch (err) {
    res
      .status(HttpStatusCodes.UNAUTHORIZED)
      .json({ msg: "Token is not valid" });
  }
}
