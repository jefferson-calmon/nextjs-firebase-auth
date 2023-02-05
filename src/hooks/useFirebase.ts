import * as firebase from 'firebase/app';
import * as database from 'firebase/database';
import * as firestore from 'firebase/firestore';
import * as auth from 'firebase/auth';
import * as storage from 'firebase/storage';

export function useFirebase(app: firebase.FirebaseApp) {

	const Auth = auth.getAuth(app);
	const Storage = storage.getStorage(app);
	const Database = database.getDatabase(app);
	const Firestore = firestore.getFirestore(app);

	const dbRef = (...paths: string[]) =>
		database.ref(Database, paths.join('/'));

	return {
		Auth,
		Storage,
		Database,
		Firestore,
		dbRef,
	} as const;
}
