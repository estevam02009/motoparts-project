import mongoose from 'mongoose';
import bcrypt from 'bcrypt';

export type UserRole = 'customer' | 'admin';

export interface IUser {
    _id: string;
    name: string;
    email: string;
    password: string;
    role: UserRole;
    createdAt: Date;
    updatedAt: Date;
}

const userSchema = new mongoose.Schema<IUser>({
    name: {
        type: String,
        required: true,
        trim: true,
    },
    email: {
        type: String,
        required: true,
        lowercase: true,
        trim: true,
        unique: true,
    },
    password: {
        type: String,
        required: true,
        trim: true,
    },
    role: {
        type: String,
        enum: ['customer', 'admin'],
        default: 'customer',
    },
}, {
    timestamps: true,
});

userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) return next();
    const salt = await bcrypt.genSalt(10);
    // @ts-ignore
    this.password = await bcrypt.hash(this.password, salt);
    next();
})

userSchema.methods.comparePassword = async function (candidate: string) {
    return await bcrypt.compare(candidate, this.password);
}

const User = mongoose.model<IUser>('User', userSchema);