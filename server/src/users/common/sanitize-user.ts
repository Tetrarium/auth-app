import { UserDocument } from '../schemas/user.schema';

export const sanitizeUser = (user: UserDocument | null) => {
  if (!user) return null;

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { password, __v, ...safeUser } = user.toObject();

  return safeUser;
};
