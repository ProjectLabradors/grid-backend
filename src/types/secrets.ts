/** @format */

import dotenv from 'dotenv';

export const VERSION = 'v1';
export const ENVIRONMENT = process.env.NODE_ENV;

dotenv.config({ path: ENVIRONMENT === 'test' ? '.env.ci' : '.env.local' });

const required = [
  'MONGODB_URI',
  'JWT_SECRET',
  'JWT_EXPIRATION',
  'SENDGRID_API_USERNAME',
  'SENDGRID_API_PASSWORD',
  'CLIENT_URL',
  'FROM_EMAIL',
];

required.forEach((value: string) => {
  if (!process.env[value]) {
    console.log(`Set ${value} environment variable.`);
    process.exit(1);
  }
});

export const MONGODB_URI = process.env.MONGODB_URI;
export const JWT_SECRET = process.env.JWT_SECRET;
export const JWT_EXPIRATION = process.env.JWT_EXPIRATION;
export const SENDGRID_API_USERNAME = process.env.SENDGRID_API_USERNAME;
export const SENDGRID_API_PASSWORD = process.env.SENDGRID_API_PASSWORD;
export const CLIENT_URL = process.env.CLIENT_URL;
export const FROM_EMAIL = process.env.FROM_EMAIL;
