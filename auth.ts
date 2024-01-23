import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import {z} from 'zod';
import {sql} from '@vercel/postgres';
import type {User} from '@/app/lib/definitions';
import bcrypt from 'bcrypt';


async function getUser(email: string): Promise<User | null> {
    try{
        const data = await sql<User>`SELECT * FROM users WHERE email = ${email}`;
        return data.rows[0];    
    }catch(error){
        console.error('Failed to fetch user:', error);
        throw new Error('Failed to fetch user.');
    }
}

export const { auth, signIn, signOut } = NextAuth({
    //...展开运算符会用authConfig中的值覆盖默认值
  ...authConfig,
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);
        
        if (parsedCredentials.success) {
            const { email, password } = parsedCredentials.data;
            const user = await getUser(email);
            if (user) {
                const isValid = await bcrypt.compare(password, user.password);
                if (isValid) {
                return user;
                }
            }
            }
            console.log('Invalid credentials');
            return null;
      },
    }),
    ],
});