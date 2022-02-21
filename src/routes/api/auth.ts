/** @format */

import bcrypt from 'bcryptjs';
import { Router, Response } from 'express';
import { check, validationResult } from 'express-validator/check';
import HttpStatusCodes from 'http-status-codes';
import jwt from 'jsonwebtoken';
import auth from '../../middleware/auth';
import Payload from '../../types/Payload';
import Request from '../../types/Request';
import { User, IUser } from '../../models/User';
import { UserToken } from '../../models/Token';
import sendEmail from '../../utils/sendEmail';
import { JWT_SECRET, JWT_EXPIRATION, CLIENT_URL } from '../../types/secrets';
import * as crypto from 'crypto';
import Profile from '../../models/Profile';

const router: Router = Router();

// @route   GET api/auth
// @desc    Get authenticated user given the token
// @access  Private
router.get('/', auth, async (req: Request, res: Response) => {
  try {
    const user: IUser = await User.findById(req.userId).select('-password');
    res.json(user);
  } catch (err) {
    console.error(err.message);
    res.status(HttpStatusCodes.INTERNAL_SERVER_ERROR).send('Server Error');
  }
});

// @route   POST api/auth
// @desc    Login user and get token
// @access  Public
router.post(
  '/',
  [
    check('email', 'Please include a valid email').isEmail(),
    check('password', 'Password is required').exists(),
  ],
  async (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res
        .status(HttpStatusCodes.BAD_REQUEST)
        .json({ errors: errors.array() });
    }

    const { email, password } = req.body;
    try {
      let user: IUser = await User.findOne({ email });

      if (!user) {
        return res.status(HttpStatusCodes.BAD_REQUEST).json({
          errors: [
            {
              msg: 'Invalid Credentials',
            },
          ],
        });
      }

      if (!user.isEmailConfirmed) {
        return res.status(HttpStatusCodes.BAD_REQUEST).json({
          errors: [
            {
              msg: 'Please confirm your email to Login into the system.',
            },
          ],
        });
      }

      const { error, isMatch } = user.comparePassword(password);

      if (error) {
        return res.status(HttpStatusCodes.BAD_REQUEST).json({
          errors: [
            {
              msg: 'Could not compare your passwords',
            },
          ],
        });
      }
      if (!isMatch) {
        return res.status(HttpStatusCodes.BAD_REQUEST).json({
          errors: [
            {
              msg: 'Invalid Credentials',
            },
          ],
        });
      }

      const payload: Payload = {
        userId: user.id,
      };

      jwt.sign(
        payload,
        JWT_SECRET,
        { expiresIn: JWT_EXPIRATION },
        (err, token) => {
          if (err) throw err;
          res.json({ token });
        }
      );
    } catch (err) {
      console.error(err.message);
      res.status(HttpStatusCodes.INTERNAL_SERVER_ERROR).send('Server Error');
    }
  }
);

// @route   POST api/auth/forgotpassword/:email
// @desc    Sends password reset token to change the password
// @access  Public
router.post('/forgotpassword/:email', async (req: Request, res: Response) => {
  const user = await User.findOne({ email: req.params.email });
  if (!user)
    res.status(HttpStatusCodes.BAD_REQUEST).send('Email does not exist');
  let token = await UserToken.findOne({ userId: user._id });
  if (token) await token.deleteOne();

  let resetToken = crypto.randomBytes(32).toString('hex');
  const hash = await bcrypt.hash(resetToken, 10);

  let profile = await Profile.findOne({ user: user._id });

  await new UserToken({
    userId: user._id,
    token: hash,
    tokenType: 'resetpassword',
    createdAt: Date.now(),
  }).save();

  const link = `${CLIENT_URL}/passwordReset?token=${resetToken}&id=${user._id}`;
  try {
    sendEmail(
      user.email,
      'Password Reset Request',
      {
        name: profile.firstName,
        link: link,
      },
      './template/requestResetPassword.handlebars'
    );
    res
      .status(HttpStatusCodes.OK)
      .send('Password reset email sent successfully..');
  } catch (err) {
    console.error(err.message);
    res.status(HttpStatusCodes.INTERNAL_SERVER_ERROR).send(err.message);
  }
});

// @route   POST api/auth/resetpassword
// @desc    Resets the password
// @access  Public
router.post(
  '/resetpassword',
  [
    check('userId', 'User id is required').not().isEmpty(),
    check('token', 'Token is required').not().isEmpty(),
    check('password', 'Password is required').not().isEmpty(),
  ],
  async (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res
        .status(HttpStatusCodes.BAD_REQUEST)
        .json({ errors: errors.array() });
    }

    const { userId, token, password } = req.body;
    let passwordResetToken = await UserToken.findOne({
      userId,
      tokenType: 'resetpassword',
    });
    if (!passwordResetToken) {
      res
        .status(HttpStatusCodes.BAD_REQUEST)
        .send('Invalid or expired password reset token');
    }
    const isValid = await bcrypt.compare(token, passwordResetToken.token);
    if (!isValid) {
      res
        .status(HttpStatusCodes.BAD_REQUEST)
        .send('Invalid or expired password reset token');
    }

    try {
      const hash = await bcrypt.hash(password, 10);

      await User.updateOne(
        { _id: userId },
        { $set: { password: hash } },
        { new: true }
      );
      await passwordResetToken.deleteOne();
      res.status(HttpStatusCodes.OK).send('Password changed successfully..');
    } catch (err) {
      console.error(err.message);
      res.status(HttpStatusCodes.INTERNAL_SERVER_ERROR).send('Server Error');
    }
  }
);

export default router;
