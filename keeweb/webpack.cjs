const path = require('path')
const webpack = require('webpack')

module.exports = {
    mode: 'production',
    devtool: false,
    target: ['web', 'es2020'],
    entry: {
        viewer: path.join(__dirname, 'src', 'viewer.js'),
        main: path.join(__dirname, 'src', 'main.js'),
        'argon2-worker': path.join(__dirname, 'src', 'argon2-worker.js'),
    },
    output: {
        path: path.join(__dirname, 'js'),
        filename: '[name].js',
        globalObject: 'self',
        clean: true,
    },
    optimization: {
        splitChunks: false,
        runtimeChunk: false,
    },
    resolve: {
        alias: {
            vue$: 'vue/dist/vue.runtime.esm-bundler.js',
        },
        fallback: {
            crypto: false,
            stream: false,
            buffer: false,
            string_decoder: false,
            path: false,
            url: false,
        },
    },
    plugins: [
        new webpack.DefinePlugin({
            __VUE_OPTIONS_API__: JSON.stringify(true),
            __VUE_PROD_DEVTOOLS__: JSON.stringify(false),
            __VUE_PROD_HYDRATION_MISMATCH_DETAILS__: JSON.stringify(false),
        }),
    ],
    performance: {
        hints: false,
    },
}
