import * as auth from 'firebase/auth';
import * as app from 'firebase/app';

export interface AuthContextProps<Role extends string> {
	children: React.ReactNode | JSX.Element;
	appId: string;
	roles: Record<Role, string>;
	permissions: Record<Role, UserPermissions<Role>>;
	loader: JSX.Element;

	privateRoutes: string[];
	publicRoutes: string[];
	disabledAuthRoutes: string[];

	firebaseApp: app.FirebaseApp;
}

export interface AuthContextData<
	Role extends string = string,
	U extends object = Record<string, never>
> {
	isAuthenticated: boolean;
	isLoading: boolean;
	isPrivateRoute: boolean;
	isPublicRoute: boolean;
	user: User | null;
	permissions: UserPermissions<Role> | undefined;
	login: (...props: LoginProps<Role>) => Promise<void>;
	logout: () => void;
	register: (...props: RegisterProps<Role>) => Promise<User | null>;
	fetchSignInMethodsForEmail: (email: string) => Promise<string[]>;
	getUser: (userId: string) => Promise<U | null>;
	verifyIfUserAlreadyLoggedIn: () => boolean;
	verifyIfUserExists: (userId: string) => Promise<boolean>;
	verifyIfRouteIsPrivate: (route: string) => boolean;
	verifyIfRouteIsPublic: (route: string) => boolean;
	verifyIfRouteIsAuthDisabled: (route: string) => boolean;
	verifyIfRouteIsAllowed: (
		p: UserPermissions<Role> | null,
		r: string
	) => boolean;
}

export interface User {
	id: string;
	name: string;
	email: string;
	photoURL: string | null;
	createdAt: string;
}

export interface FirebaseConfig {
	apiKey: string;
	authDomain: string;
	projectId: string;
	storageBucket: string;
	messagingSenderId: string;
	appId: string;
	measurementId: string;
	databaseURL: string;
}

export interface UserPermissions<Role extends string> {
	role: Role;
	mainRoute: string;
	allowedRoutes: string[];
	restrictedRoutes: string[];
}

export interface LoginUser {
	email: string;
	password: string;
}

export interface RegisterUser extends Omit<User, 'id' | 'createdAt'> {
	password?: string;
}

export type LoggerProps<Role extends string> = [
	data: LoginUser | RegisterUser | null,
	role: Role,
	provider: Provider,
	options: Options | undefined,
	type: 'login' | 'register'
];

export type LoginProps<Role extends string> = [
	data: LoginUser | null,
	role: Role,
	provider: Provider,
	options?: Options | undefined
];

export type RegisterProps<Role extends string> = [
	user: RegisterUser | null,
	role: Role,
	provider: Provider,
	options?: Options | undefined
];

export type AfterLoginSetCookies<Role extends string> = [
	user: auth.User,
	permissions: UserPermissions<Role>,
	options?: Options
];

export type AfterLoginRedirect<Role extends string> = [
	permissions: UserPermissions<Role>,
	options?: Options
];

export interface Options {
	// General
	remember?: boolean;
	redirectAfterLogin?: boolean;

	// Register
	loginAfterRegistration?: boolean;
	userData?: Record<string, never>;
}

// Types
export type SignIn = [email: string, password: string];
export type Provider = 'email/password' | 'google';
