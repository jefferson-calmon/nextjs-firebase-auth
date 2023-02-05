import { useRouter } from 'next/router';
import {
	createContext,
	useState,
	useEffect,
	useCallback,
	useMemo,
} from 'react';

import * as database from 'firebase/database';
import * as auth from 'firebase/auth';
import Cookies from 'js-cookie';

import * as T from '../types';
import ProtectRoute from '../components/ProtectRoute';
import { useFirebase } from '../hooks/useFirebase';

// Context
export const AuthContext = createContext({} as T.AuthContextData);

// Context Provider
export function AuthProvider<R extends string, U extends T.User>(
	props: T.AuthContextProps<R>
): JSX.Element {
	// Hooks
	const router = useRouter();
	const { Auth, dbRef } = useFirebase(props.firebaseApp);

	// Types
	type User = T.User | U | Record<string, string | never | null>;
	type Role = R;
	type Permissions = T.UserPermissions<Role>;
	type Register = T.RegisterProps<Role>;
	type Login = T.LoginProps<Role>;
	type Logger = T.LoggerProps<Role>;

	// States
	const [authUser, setAuthUser] = useState<auth.User | null>(null);
	const [userPermissions, setUserPermissions] = useState<Permissions>();
	const [authUserExists, setAuthUserExists] = useState<boolean>(true);
	const [isLoading, setIsLoading] = useState<boolean>(true);

	// Vars
	const route = router.route;

	// Memo vars
	const isPrivateRoute = useMemo(() => {
		return verifyIfRouteIsPrivate(router.route);
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [router.route]);

	const isPublicRoute = useMemo(() => {
		return verifyIfRouteIsPublic(router.route);
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [router.route]);

	const appId = useMemo(() => props.appId, [props.appId]);

	// Callbacks
	const push = useCallback<typeof router.push>((...props) => {
		return router.push(...props);
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, []);

	const createUser = useCallback(async (user: User | null, role: Role) => {
		if (!user) return;

		const userDbRef = dbRef(`users/${user.id}`);
		const userRoleDbRef = dbRef(`users/roles/${role}s/${user.id}`);

		await database.set(userDbRef, user);
		await database.set(userRoleDbRef, true);
	}, [dbRef]);

	const getUser = useCallback(async (userId: string) => {
		const user = await database.get(dbRef(`users/${userId}`));

		return user.val() as U | null;
	}, [dbRef]);

	const getUserPermissions = useCallback(
		async (
			userId: string,
			userRole?: Role
		): Promise<Permissions | null> => {
			const role = userRole ?? (await findUserRole(userId));

			if (!role) return null;

			return props.permissions[role];
		},
		// eslint-disable-next-line react-hooks/exhaustive-deps
		[props.permissions]
	);

	const setAuthPersistence = useCallback(async (remember: boolean) => {
		const persistence = remember
			? auth.browserLocalPersistence
			: auth.browserSessionPersistence;

		await auth.setPersistence(Auth, persistence);
	}, [Auth]);

	const loginWithEmailAndPassword = useCallback((...props: Logger) => {
		const [user] = props;

		if (!user) throw 'User is undefined';

		const email = user.email;
		const password = user.password || '';

		return auth.signInWithEmailAndPassword(Auth, email, password);
	}, [Auth]);

	const loginWithGoogle = useCallback((...props: Logger) => {
		const [] = props;

		const provider = new auth.GoogleAuthProvider();

		return auth.signInWithPopup(Auth, provider);
	}, [Auth]);

	const registerWithEmailAndPassword = useCallback(
		async (...props: Logger) => {
			const user = props[0];
			const role = props[1];
			const options = props[3];

			if (!user) throw 'User is undefined';

			const registerUser = user as T.RegisterUser;
			const email = registerUser.email;
			const password = registerUser.password || '';

			const userCredential = await auth.createUserWithEmailAndPassword(
				Auth,
				email,
				password
			);

			await auth.updateProfile(userCredential.user, {
				displayName: registerUser.name,
				photoURL: registerUser.photoURL,
			});
			await userCredential.user.reload();

			const authUser = authUserToUser(userCredential.user);

			if (options?.userData) {
				const newUser: User = {
					...options?.userData,
					...authUser,
				};

				await createUser(newUser, role);
			} else {
				await createUser(authUser, role);
			}

			return userCredential;
		},
		[createUser, Auth]
	);

	const logger = useCallback(async (...props: Logger) => {
		const provider = props[2];
		const type = props[4];

		const handlers = getAuthHandlers();

		const handler = handlers[type][provider];

		const userCredential = await handler(...props);

		return userCredential.user;
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, []);

	const afterLogin = useCallback(() => {
		function setCookies(...props: T.AfterLoginSetCookies<Role>) {
			const [user, permissions, options] = props;

			const expires = options?.remember ? 99999 : undefined;
			const secure = true;

			Cookies.set('app_id', appId, { expires, secure });
			Cookies.set('user_id', user.uid, { expires, secure });
			Cookies.set('user_role', permissions.role, { expires, secure });
		}

		function redirect(...props: T.AfterLoginRedirect<Role>) {
			const [permissions, options] = props;

			if (!options?.redirectAfterLogin) return;

			const query = window.location.search;
			const origin = new URLSearchParams(query).get('origin');

			const goTo = (path: string) => (window.location.pathname = path);

			if (origin) return goTo(origin);
			if (!origin) return goTo(permissions.mainRoute);

			return;
		}

		return {
			setCookies,
			redirect,
		};
	}, [appId]);

	const login = useCallback(
		async (...props: Login) => {
			const [, role, , options] = props;

			await setAuthPersistence(!!options?.remember);

			const authUser = await logger(...props, 'login');
			if (!authUser) throw 'Auth user is null';

			const permissions = await getUserPermissions(authUser.uid, role);
			if (!permissions) throw 'User permissions not found';

			afterLogin().setCookies(authUser, permissions, options);
			afterLogin().redirect(permissions, options);

			setAuthUser(authUser);
			setUserPermissions(permissions);
		},
		[setAuthPersistence, logger, getUserPermissions, afterLogin]
	);

	const register = useCallback(
		async (...props: Register) => {
			const [, role, , options] = props;

			await setAuthPersistence(!!options?.remember);

			const authUser = await logger(...props, 'register');
			if (!authUser) throw 'Auth user is null';

			const permissions = await getUserPermissions(authUser.uid, role);
			if (!permissions) throw 'User permissions not found';

			if (options?.loginAfterRegistration) {
				afterLogin().setCookies(authUser, permissions, options);
				afterLogin().redirect(permissions, options);

				setAuthUser(authUser);
				setUserPermissions(permissions);
			}

			return authUserToUser(authUser);
		},
		[afterLogin, getUserPermissions, logger, setAuthPersistence]
	);

	const logout = useCallback(async () => {
		Cookies.remove('app_id');
		Cookies.remove('user_id');
		Cookies.remove('user_role');

		sessionStorage.setItem('user:logout', 'true');

		setIsLoading(true);
		auth.signOut(Auth);
		setAuthUser(null);
		setUserPermissions(undefined);
	}, [Auth]);

	// Effects
	useEffect(() => {
		auth.onAuthStateChanged(Auth, async (authUser) => {
			if (!authUser) return setAuthUserExists(false);

			setAuthUser(authUser);
			setAuthUserExists(true);
		});
	}, [Auth]);

	useEffect(() => {
		if (!authUser) return;

		setIsLoading(true);

		// If user is logged in, get user permissions
		(async () => {
			const userPermissions = await getUserPermissions(authUser.uid);

			if (!userPermissions) return setIsLoading(false);

			setUserPermissions(userPermissions);
			setIsLoading(false);
		})();
	}, [authUser, getUserPermissions, push, setUserPermissions]);

	useEffect(() => {
		const origin = window.location.pathname;
		const query: Record<string, string> = {};
		const userSignOut = sessionStorage.getItem('user:logout');

		if (authUserExists) return;
		if (!verifyIfRouteIsPrivate(route)) return setIsLoading(false);

		if (route !== '/login' && !userSignOut) {
			query.origin = origin;
			alert('Você precisa estar logado para acessar essa página.');
			logout();
		}

		push({
			pathname: '/login',
			query,
		})
			.then(() => sessionStorage.removeItem('user:logout'))
			.finally(() => setIsLoading(false));
		// eslint-disable-next-line react-hooks/exhaustive-deps
	}, [authUserExists, push]);

	// Functions
	function authUserToUser(authUser: auth.User | null) {
		if (!authUser) return null;

		const creationTime = authUser.metadata.creationTime;

		const user: T.User = {
			id: authUser.uid,
			name: authUser.displayName || 'unknown',
			email: authUser.email || '',
			photoURL: authUser.photoURL,
			createdAt: new Date(creationTime || '').toISOString(),
		};

		return user;
	}

	function getAuthHandlers() {
		return {
			login: {
				google: loginWithGoogle,
				'email/password': loginWithEmailAndPassword,
			},
			register: {
				google: loginWithGoogle,
				'email/password': registerWithEmailAndPassword,
			},
		};
	}

	function fetchSignInMethodsForEmail(email: string) {
		return auth.fetchSignInMethodsForEmail(Auth, email);
	}

	function verifyIfRouteIsPrivate(route: string) {
		const isPrivateRoute = props.privateRoutes.some((privateRoute) => {
			const regex = new RegExp(privateRoute.replace('*', '.*'));

			return regex.test(route);
		});

		return isPrivateRoute;
	}

	function verifyIfRouteIsPublic(route: string) {
		const isPublicRoute = props.publicRoutes.some((publicRoute) => {
			const regex = new RegExp(publicRoute.replace('*', '.*'));

			return regex.test(route);
		});

		return isPublicRoute;
	}

	function verifyIfRouteIsAllowed(p: Permissions | null, r: string) {
		const permissions = p;
		const route = r;

		// Verify if route is public
		if (!verifyIfRouteIsPrivate(route)) return true;
		if (verifyIfRouteIsPublic(route)) return true;

		// Verify if user is logged
		if (!permissions) return false;

		const restrictedRoutes = permissions.restrictedRoutes;
		const allowedRoutes = permissions.allowedRoutes;

		const isAllowed = allowedRoutes.some((allowedRoute) => {
			const regex = new RegExp(allowedRoute.replace('*', '.*'));

			return regex.test(route);
		});

		const isRestricted = restrictedRoutes.some((restrictedRoute) => {
			const regex = new RegExp(restrictedRoute.replace('*', '.*'));

			return regex.test(route);
		});

		return isAllowed && !isRestricted;
	}

	function verifyIfRouteIsAuthDisabled(route: string) {
		return props.disabledAuthRoutes.includes(route);
	}

	function verifyIfUserAlreadyLoggedIn() {
		const userId = Cookies.get('user_id');
		const userRole = Cookies.get('user_role');
		const id = Cookies.get('app_id');

		if (!userId || !userRole || !appId) return false;
		if (id !== appId) return false;

		return true;
	}

	async function verifyIfUserExists(userId: string): Promise<boolean> {
		const user = await database.get(dbRef(`/users/${userId}`));

		return user.exists();
	}

	async function findUserRole(userId: string): Promise<Role | null> {
		const roles = Object.keys(props.roles) as Role[];
		let userRole: Role | null = null;

		await Promise.all(
			roles.map(async (role) => {
				const userDbRef = dbRef(`users/roles/${role}s/${userId}`);
				const user = await database.get(userDbRef);

				if (user.exists()) userRole = role;
			})
		);

		return userRole;
	}

	const Context = AuthContext as unknown as React.Context<
		T.AuthContextData<Role, U>
	>;

	return (
		<Context.Provider
			value={{
				isAuthenticated: !!authUser && !!userPermissions,
				isLoading,
				isPrivateRoute,
				isPublicRoute,
				user: authUserToUser(authUser),
				login,
				logout,
				register,
				permissions: userPermissions,
				fetchSignInMethodsForEmail,
				getUser,
				verifyIfUserAlreadyLoggedIn,
				verifyIfUserExists,
				verifyIfRouteIsPrivate,
				verifyIfRouteIsPublic,
				verifyIfRouteIsAllowed,
				verifyIfRouteIsAuthDisabled,
			}}
		>
			<ProtectRoute loader={props.loader}>{props.children}</ProtectRoute>
		</Context.Provider>
	);
}
