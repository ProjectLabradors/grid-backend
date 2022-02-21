/** @format */

import * as nodemailer from 'nodemailer';
import * as handlebars from 'handlebars';
import * as fs from 'fs';
import * as path from 'path';
import { SENDGRID_API_USERNAME, SENDGRID_API_PASSWORD } from '../types/secrets';

const sendEmail = async (
  email: string,
  subject: string,
  payload: any,
  template: string
) => {
  try {
    const transporter = nodemailer.createTransport({
      host: 'smtp.sendgrid.net',
      port: 465,
      secure: true,
      auth: {
        user: SENDGRID_API_USERNAME,
        pass: SENDGRID_API_PASSWORD,
      },
    });

    const source = fs.readFileSync(path.join(__dirname, template), 'utf8');
    const compiledTemplate = handlebars.compile(source);
    const options = () => {
      return {
        from: process.env.FROM_EMAIL,
        to: email,
        subject: subject,
        html: compiledTemplate(payload),
      };
    };

    // Send email
    transporter.sendMail(options(), (error, info) => {
      if (error) {
        console.log(error);
        return error;
      } else {
        return {
          success: true,
        };
      }
    });
  } catch (error) {
    console.log(error);
    return error;
  }
};

/*
  Example:
  sendEmail(
    "youremail@gmail.com,
    "Email subject",
    { name: "Eze" },
    "./templates/layouts/main.handlebars"
  );
  */

export default sendEmail;
