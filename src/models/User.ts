/** @format */

import { Document, Model, model, Schema } from 'mongoose';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

/**
 * Interface to model the User Schema for TypeScript.
 * @param email:string
 * @param password:string
 * @param avatar:string
 * @param isEmailConfirmed:boolean
 */
export interface IUser extends Document {
  email: string;
  password: string;
  avatar: string;
  isEmailConfirmed: boolean;
  comparePassword: Function;
}

const userSchema: Schema = new Schema({
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
  },
  avatar: {
    type: String,
  },
  isEmailConfirmed: {
    type: Boolean,
    default: false,
  },
  date: {
    type: Date,
    default: Date.now,
  },
});

export type UserDocument = mongoose.Document & IUser;
/**
 * Password hash middleware.
 */
userSchema.pre('save', function save(next) {
  const user = this as UserDocument;
  if (!user.isModified('password')) {
    return next();
  }
  bcrypt.genSalt(10, (err, salt) => {
    if (err) {
      return next(err);
    }
    bcrypt.hash(user.password, salt, (err: mongoose.Error, hash) => {
      if (err) {
        return next(err);
      }
      user.password = hash;
      next();
    });
  });
});

const comparePassword = function (candidatePassword: string) {
  try {
    const isMatch = bcrypt.compareSync(candidatePassword, this.password);
    return { isMatch };
  } catch (error) {
    return { error };
  }
};

userSchema.methods.comparePassword = comparePassword;

export const User =
  mongoose.models.User || mongoose.model<UserDocument>('User', userSchema);
