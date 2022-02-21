/** @format */

import bcrypt from 'bcryptjs';
import { Router, Response } from 'express';
import { check, validationResult } from 'express-validator/check';
import gravatar from 'gravatar';
import HttpStatusCodes from 'http-status-codes';
import jwt from 'jsonwebtoken';
import Payload from '../../types/Payload';
import Request from '../../types/Request';
import { User, IUser } from '../../models/User';
import { UserToken } from '../../models/Token';
import { CLIENT_URL } from '../../types/secrets';
import sendEmail from '../../utils/sendEmail';
import * as crypto from 'crypto';

const router: Router = Router();

// @route   GET api/emailcheck
// @desc    Checks whether the user email id already exists or not
// @access  Public

router.get('/emailcheck/:email', async (_req: Request, res: Response) => {
  try {
    let message = '';
    let user: IUser = await User.findOne({ email: _req.params.email });
    if (user) {
      message = 'User already exists';
    } else {
      message = 'New user';
    }
    return res.status(HttpStatusCodes.OK).json({
      errors: [
        {
          msg: message,
        },
      ],
    });
  } catch (err) {
    console.error(err.message);
    res.status(HttpStatusCodes.INTERNAL_SERVER_ERROR).send('Server Error');
  }
});

// @route   POST api/user
// @desc    Register user given their email and password, returns the message upon successful registration
// @access  Public
router.post(
  '/',
  [
    check('email', 'Please include a valid email').isEmail(),
    check(
      'password',
      'Please enter a password with 8 or more characters'
    ).isLength({ min: 8 }),
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

      if (user) {
        return res.status(HttpStatusCodes.BAD_REQUEST).json({
          errors: [
            {
              msg: 'User already exists',
            },
          ],
        });
      }

      const options: gravatar.Options = {
        s: '200',
        r: 'pg',
        d: 'mm',
      };

      const avatar = gravatar.url(email, options);

      const salt = await bcrypt.genSalt(10);
      const hashed = await bcrypt.hash(password, salt);

      // Build user object based on IUser
      const userFields = {
        email,
        password,
        avatar,
      };

      user = new User(userFields);

      await user.save();

      let token = await UserToken.findOne({ userId: user._id });
      if (token) await token.deleteOne();

      let confirmToken = crypto.randomBytes(32).toString('hex');
      const hash = await bcrypt.hash(confirmToken, 10);

      await new UserToken({
        userId: user._id,
        token: hash,
        tokenType: 'emailconfirm',
        createdAt: Date.now(),
      }).save();

      const link = `${CLIENT_URL}/emailconfirm?token=${confirmToken}&id=${user._id}`;

      sendEmail(
        user.email,
        'Welcome to Project Labrador! Confirm Your Email',
        {
          link: link,
        },
        './template/emailconfirm.handlebars'
      );
      const payload: Payload = {
        userId: user.id,
      };
      res
        .status(HttpStatusCodes.OK)
        .send('Confirmation email sent successfully..');
    } catch (err) {
      console.error(err.message);
      res.status(HttpStatusCodes.INTERNAL_SERVER_ERROR).send('Server Error');
    }
  }
);

router.post(
  '/confirmemail',
  [
    check('userId', 'User id is required').not().isEmpty(),
    check('token', 'Token is required').not().isEmpty(),
  ],
  async (req: Request, res: Response) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res
        .status(HttpStatusCodes.BAD_REQUEST)
        .json({ errors: errors.array() });
    }
    const { userId, token } = req.body;
    try {
      let user: IUser = await User.findById(userId);
      if (!user) {
        return res.status(HttpStatusCodes.BAD_REQUEST).json({
          errors: [
            {
              msg: 'User with this id does not exist',
            },
          ],
        });
      }
    } catch (err) {
      res.status(HttpStatusCodes.BAD_REQUEST).json({
        errors: [
          {
            msg: 'User with this id does not exist',
          },
        ],
      });
    }

    let confirmToken = await UserToken.findOne({
      userId,
      tokenType: 'emailconfirm',
    });
    if (!confirmToken) {
      res
        .status(HttpStatusCodes.BAD_REQUEST)
        .send('Invalid or expired confirm token');
    }
    const isValid = await bcrypt.compare(token, confirmToken.token);
    if (!isValid) {
      res
        .status(HttpStatusCodes.BAD_REQUEST)
        .send('Invalid or expired confirm token');
    }

    try {
      await User.updateOne(
        { _id: userId },
        { $set: { isEmailConfirmed: true } }
      );
      await confirmToken.deleteOne();
      res
        .status(HttpStatusCodes.OK)
        .send('User email confirmed successfully..');
    } catch (err) {
      console.error(err.message);
      res.status(HttpStatusCodes.INTERNAL_SERVER_ERROR).send('Server Error');
    }
  }
);

router.post('/sendconfirmtoken/:email', async (req: Request, res: Response) => {
  let user: IUser = await User.findOne({ email: req.params.email });
  if (!user) {
    return res.status(HttpStatusCodes.BAD_REQUEST).json({
      errors: [
        {
          msg: 'User with this email does not exist',
        },
      ],
    });
  }
  try {
    let token = await UserToken.findOne({ userId: user._id });
    if (token) await token.deleteOne();

    let confirmToken = crypto.randomBytes(32).toString('hex');
    const hash = await bcrypt.hash(confirmToken, 10);

    await new UserToken({
      userId: user._id,
      token: hash,
      tokenType: 'emailconfirm',
      createdAt: Date.now(),
    }).save();

    const link = `${CLIENT_URL}/emailconfirm?token=${confirmToken}&id=${user._id}`;

    sendEmail(
      user.email,
      'Welcome to Project Labrador! Confirm Your Email',
      {
        link: link,
      },
      './template/emailconfirm.handlebars'
    );

    res
      .status(HttpStatusCodes.OK)
      .send('Confirmation email sent successfully..');
  } catch (error) {}
});

export default router;
