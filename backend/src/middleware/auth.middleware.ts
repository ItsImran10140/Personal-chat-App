import jwt from "jsonwebtoken";
import User from "../models/user.model";
import { Request, Response } from "express";

export const protectRoute = async (req: Request, res: Response, next: any) => {
  try {
    const token = req.cookies.jwt;

    if (!token) {
      res.status(401).json({ message: "Unauthorized - No Token Provided" });
      return;
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || "");

    if (!decoded) {
      res.status(401).json({ message: "Unauthorized - Invalid Token" });
      return;
    }

    const user = await User.findById((decoded as jwt.JwtPayload).userId).select(
      "-password"
    );

    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    (req as any).user = user;

    next();
  } catch (error) {
    console.log("Error in protectRoute middleware: ");
    res.status(500).json({ message: "Internal server error" });
  }
};
