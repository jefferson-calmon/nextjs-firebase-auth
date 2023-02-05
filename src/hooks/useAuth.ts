import { useContext } from 'react';

import { AuthContextData } from '../types';
import { AuthContext } from '../contexts';

export const useAuth = <R extends string, U extends object>() => {
	return useContext<AuthContextData<R, U>>(
		AuthContext as unknown as React.Context<AuthContextData<R, U>>
	) as AuthContextData<R, U>;
};
