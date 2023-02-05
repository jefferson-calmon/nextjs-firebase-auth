## Uso

Primeiro, vamos importar o nosso pacote.

```tsx
import * as NFA from 'nextjs-firebase-auth';
```

Agora vamos definir os tipos de usuários e o modelo do usuário.

```tsx
interface User {
   id: string;
   name: string;
   email: string;
   phone: number;
   photoURL: string | null;
   createdAt: string;
}

type UserRole = 'user' | 'admin';
```

Feito isso podemos criar um component que irá retornar o nosso `AuthProvider`, passando para ele as propriedades necessárias.

```tsx
interface ContextProps {
   children: React.ReactNode | JSX.Element;
}

if (!firebase.getApps().length) firebase.initializeApp(firebaseConfig);
const app = firebase.getApp();

export function AuthProvider(props: ContextProps) {
   return (
      // Estamos passando aqui os parâmetros de tipo
      <NFA.AuthProvider<UserRole, User>
         // Id único para cada projeto
         appId="unique-project-id"
         // Componente que será renderizado quando a autenticação estiver carregando
         loader={<LoadingFullScreen />}
         // Objeto com os tipos de usuários com os seus nomes personalizados
         roles={{
            user: 'Usuário',
            admin: 'Administrador',
         }}
         // Rotas que o fluxo de validação da autenticação será pulada
         disabledAuthRoutes={['/login']}
         // Rotas privadas da aplicação (Importante incluir todas)
         privateRoutes={['/dashboard*', '/panel*']}
         // Rotas públicas da aplicação (Importante incluir todas)
         publicRoutes={['/', '/login', '/register', '/forgot-password']}
         // Permissões para cada tipo de usuário
         permissions={{
            admin: {
               role: 'admin',
               mainRoute: '/dashboard',
               allowedRoutes: ['*'],
               restrictedRoutes: [],
            },
            user: {
               role: 'user',
               mainRoute: '/panel',
               allowedRoutes: ['/panel*'],
               restrictedRoutes: [],
            },
         }}
         // Firebase app
         firebaseApp={app}
      >
         {props.children}
      </NFA.AuthProvider>
   );
}
```

Feito isso, já podemos configurar o nosso hook `useAuth` passando para ele os nossos parâmetros de tipo.

```tsx
export const useAuth = () => NFA.useAuth<UserRole, User>();
```

Pronto, o seu contexto de autenticação deve ter ficado mais ou menos assim.

```tsx
import * as NFA from 'nextjs-firebase-auth';
import * as firebase from 'firebase/app';

import LoadingFullscreen from 'components/LoadingFullscreen';
import { firebaseConfig } from '../../firebaseConfig';

interface ContextProps {
   children: React.ReactNode | JSX.Element;
}

interface User {
   id: string;
   name: string;
   email: string;
   phone: number;
   photoURL: string | null;
   enterpriseId: string;
   createdAt: string;
}

type UserRole = 'user' | 'admin';

if (!firebase.getApps().length) firebase.initializeApp(firebaseConfig);
const app = firebase.getApp();

export function AuthProvider(props: ContextProps) {
   return (
      <NFA.AuthProvider<UserRole, User>
         appId="unique-project-id"
         loader={<LoadingFullscreen />}
         roles={{
            user: 'Usuário',
            admin: 'Administrador',
         }}
         disabledAuthRoutes={['/login']}
         permissions={{
            admin: {
               role: 'admin',
               mainRoute: '/dashboard',
               allowedRoutes: ['*'],
               restrictedRoutes: [],
            },
            user: {
               role: 'user',
               mainRoute: '/panel',
               allowedRoutes: ['/panel*'],
               restrictedRoutes: [],
            },
         }}
         privateRoutes={['/dashboard*', '/panel*']}
         publicRoutes={['/', '/login', '/register', '/forgot-password']}
         firebaseApp={app}
      >
         {props.children}
      </NFA.AuthProvider>
   );
}

export const useAuth = () => NFA.useAuth<UserRole, User>();
```
