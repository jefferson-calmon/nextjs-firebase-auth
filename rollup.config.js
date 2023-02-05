import commonjs from 'rollup-plugin-commonjs';
import resolve from 'rollup-plugin-node-resolve';
import { terser } from 'rollup-plugin-terser';
import typescript from 'rollup-plugin-typescript2';
import postCSS from 'rollup-plugin-postcss';
import svgr from '@svgr/rollup';
import url from '@rollup/plugin-url';
import babel from '@rollup/plugin-babel';

import pkg from './package.json';

function makeExternalPredicate(externalArr) {
	if (!externalArr.length) {
		return () => false;
	}

	const pattern = new RegExp(`^(${externalArr.join('|')})($|/)`);

	return (id) => pattern.test(id);
}

function getExternal() {
	const dependencies = Object.keys(pkg.dependencies || {});
	const peerDependencies = Object.keys(pkg.peerDependencies || {});

	const external = [...dependencies, ...peerDependencies];

	return makeExternalPredicate(external);
}

const config = {
	input: 'src/index.ts',
	external: getExternal(),
	output: [
		{
			// dir: 'dist',
			file: 'dist/index.js',
			format: 'cjs',
			// // preserveModules: true,
			// preserveModulesRoot: 'src',
			sourcemap: true,
		},
		{
			// dir: 'dist',
			file: 'dist/index.esm.js',
			format: 'esm',
			// preserveModules: true,
			// preserveModulesRoot: 'src',
			sourcemap: true,
		},
	],
	plugins: [
		typescript({
			tsconfigOverride: {
				compilerOptions: {
					declarationDir: 'dist',
					declarationMap: true,
				},
				include: ['**/*.ts', '**/*.tsx', '**/*.d.ts'],
			},
			tsconfig: 'tsconfig.build.json',
			rollupCommonJSResolveHack: true,
			useTsconfigDeclarationDir: true,
		}),
		url(),
		resolve(),
		babel({
			exclude: 'node_modules/**',
		}),
		commonjs(),
		terser(),
		svgr({
			babel: false,
			icon: true,
		}),
		postCSS(),
	],
};

export default config;
