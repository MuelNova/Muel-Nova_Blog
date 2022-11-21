// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const lightCodeTheme = require('prism-react-renderer/themes/github');
const darkCodeTheme = require('prism-react-renderer/themes/dracula');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'NovaNo1r メモ帳',
  tagline: 'PWN THIS ワールド',
  url: 'https://novanoir.moe',
  baseUrl: '/',
  onBrokenLinks: 'warn',
  onBrokenMarkdownLinks: 'warn',
  favicon: 'img/logo.png',

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'Nova-Noir', // Usually your GitHub org/user name.
  projectName: 'NovaNo1r-Blog', // Usually your repo name.

  // Even if you don't use internalization, you can use this field to set useful
  // metadata like html lang. For example, if your site is Chinese, you may want
  // to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'zh-Hans',
    locales: ['zh-Hans', 'en'],
  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          // id: "posts",
          path: 'posts',
          routeBasePath: 'posts',
          sidebarPath: require.resolve('./sidebars.js'),
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl:
            'https://github.com/Nova-Noir/NovaNo1r-Blog/tree/main/',
          
        },
        sitemap: {
          changefreq: 'weekly',
          priority: 0.5,
          ignorePatterns: ['/tags/**'],
          filename: 'sitemap.xml',
        },
        blog: {
          blogTitle: 'BLOG',
          blogSidebarTitle: 'Written with 😢tears and loves❤',
          blogSidebarCount: 'ALL',
          showReadingTime: true,
          // Please change this to your repo.
          // Remove this to remove the "edit this page" links.
          editUrl:
            'https://github.com/Nova-Noir/NovaNo1r-Blog/tree/main/',
          feedOptions: {
            type: 'rss',
            copyright: `Copyright © ${new Date().getFullYear()} NovaNo1r with ❤`,
          },
        },
        theme: {
          customCss: require.resolve('./src/css/custom.css'),
        },
      }),
    ],
  ],

  plugins: [
    [
      '@docusaurus/plugin-content-docs',
      {
        id: 'blockchain',
        path: 'blockchain',
        routeBasePath: 'blockchain',
      }
    ],
    [
      '@docusaurus/plugin-content-docs',
      {
        id: 'pwn',
        path: 'pwn',
        routeBasePath: 'pwn',
      }
    ],

    [
      '@docusaurus/plugin-content-blog',
      {
        id: 'reproducing',
        routeBasePath: 'reproducing',
        path: 'reproducing',
        feedOptions: {
          type: 'rss',
          copyright: `Copyright © ${new Date().getFullYear()} NovaNo1r with ❤`,
        },
        authorsMapPath: "../blog/authors.yml"
      },
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      navbar: {
        title: 'Nova-Noir',
        logo: {
          alt: 'SiteLogo',
          src: 'img/logo.png',
        },
        items: [
          // {
          //   type: 'doc',
          //   docId: '',
          //   position: 'right',
          //   label: '🤡文章',
          // },
          {to: '/posts', label: '🤡文章', position: 'right'},
          {to: '/reproducing', label: '♻️复现', position: 'right'},
          {
            type: 'localeDropdown',
            position: 'right',
          },
          {to: '/blog', label: '📝Blog', position: 'left'},
          {to: '/blockchain', label: '📈Blockchain', position: 'left'},
          {to: '/pwn', label: '♿️Pwn', position: 'left'},
          {
            href: 'https://github.com/Nova-Noir',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Here',
            items: [
              {to: '/blog', label: '📝Blog'},
              {to: '/blockchain', label: '📈Blockchain'},
              {to: '/pwn', label: '♿️Pwn'},
            ],
          },
          {
            title: 'There',
            items: [
              {to: '/reproducing', label: '♻️复现'},
              {to: '/posts', label: '🤡文章'},
            ],
          },
          {
            title: 'Community',
            items: [
              {
                label: 'Teamspeak',
                href: '#',
              },
              {
                label: 'Discord',
                href: '#',
              },
              {
                label: 'Twitter',
                href: '#',
              },
            ],
          },
          {
            title: 'More',
            items: [
              {
                label: 'DEV',
                href: 'https://novanoir.dev'
              },
              {
                label: 'GitHub',
                href: 'https://github.com/Nova-Noir',
              }
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} <a href="/about">Nova-Noir</a>. Built with <a href="https://docusaurus.io/">Docusaurus</a> filling with ❤ and 🥛`,
      },
      prism: {
        theme: lightCodeTheme,
        darkTheme: darkCodeTheme,
        additionalLanguages: ['powershell', 'bash']
      },
      tableOfContents: {
        minHeadingLevel: 2,
        maxHeadingLevel: 5,
      }
    }),
};

module.exports = config;
