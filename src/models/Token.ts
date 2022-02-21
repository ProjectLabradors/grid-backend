/** @format */

import { Document, Model, model, Schema } from 'mongoose';
import mongoose from 'mongoose';
import { IUser } from "./User";

/**
 * Interface to model the User Schema for TypeScript.
 * @param email:string
 * @param password:string
 * @param avatar:string
 */
export interface IUserToken extends Document {
  userId: IUser['_id'];
  token: string;
  tokenType: string;
}

const userTokenSchema: Schema = new Schema({
  userId: {
    type: Schema.Types.ObjectId,
    required: true,
    ref: 'User',
  },
  token: {
    type: String,
    required: true,
  },
  tokenType: {
    type: String,
    required: true,
  },
  createdAt: {
    type: Date,
    required: true,
    default: Date.now,
    expires: 900,
  },
});

export type UserTokenDocument = mongoose.Document & IUserToken;

export const UserToken = mongoose.model<UserTokenDocument>('UserToken', userTokenSchema);

