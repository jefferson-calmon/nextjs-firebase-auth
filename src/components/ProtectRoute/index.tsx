import Error from 'next/error';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/router';

import { useAuth } from '../../hooks';

export interface ProtectRouteProps {
	children: JSX.Element | React.ReactNode;
	loader: JSX.Element;
}

export type Render = 'undefined' | 'loading' | 'page' | 'denied';

function ProtectRoute(props: ProtectRouteProps): JSX.Element {
	// Hooks
	const router = useRouter();
	const auth = useAuth();

	// States
	const [render, setRender] = useState<Render>();

	// Vars
	const ErrorPage = () => <Error statusCode={401} title="Não autorizado" />;

	// Effects
	useEffect(() => {
		const p = auth.permissions || null;
		const r = router.route;
		const isLoading = auth.isLoading;

		const userAlreadyLoggedIn = auth.verifyIfUserAlreadyLoggedIn();
		const isAuthDisabled = auth.verifyIfRouteIsAuthDisabled(r);
		const isPublicRoute = auth.verifyIfRouteIsPublic(r);
		const isPrivateRoute = auth.verifyIfRouteIsPrivate(r);
		const isAllowedRoute = auth.verifyIfRouteIsAllowed(p, r);

		if (isAuthDisabled) return setRender('page');
		if (isLoading && isPrivateRoute) return setRender('loading');
		if (isLoading && isPublicRoute) return setRender('page');
		if (isLoading && userAlreadyLoggedIn) return setRender('loading');
		if (isAllowedRoute) return setRender('page');
		if (!isAllowedRoute) return setRender('denied');
	}, [auth, router.route]);

	if (!render) return <></>;

	if (render === 'undefined') return <></>;
	if (render === 'loading') return props.loader;
	if (render === 'page') return props.children as JSX.Element;
	if (render === 'denied') return <ErrorPage />;

	return <></>;
}

export default ProtectRoute;
