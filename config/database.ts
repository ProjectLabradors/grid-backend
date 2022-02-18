import { ConnectionOptions, connect } from "mongoose";
import { MONGODB_URI } from '../src/types/secrets';

const connectDB = async () => {
  try {
    debugger
    const mongoURI: string = MONGODB_URI;
    const options: ConnectionOptions = {
      useNewUrlParser: true,
      useCreateIndex: true,
      useFindAndModify: false,
      useUnifiedTopology: true,
    };
    await connect(mongoURI, options);
    console.log("MongoDB Connected...");
  } catch (err) {
    console.error(err.message);
    // Exit process with failure
    process.exit(1);
  }
};

export default connectDB;
