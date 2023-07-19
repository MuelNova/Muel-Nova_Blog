// dotenv
require('dotenv').config();

// @ts-check
// Note: type annotations allow type checking and IDEs autocompletion

const lightCodeTheme = require('prism-react-renderer/themes/github');
const darkCodeTheme = require('prism-react-renderer/themes/dracula');

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'ネコのメモ帳',
  tagline: 'Meow~',
  url: 'https://n.ova.moe',
  baseUrl: '/',
  onBrokenLinks: 'warn',
  onBrokenMarkdownLinks: 'warn',
  favicon: 'img/logo.png',
  staticDirectories: ['static'],

  // GitHub pages deployment config.
  // If you aren't using GitHub pages, you don't need these.
  organizationName: 'MuelNova', // Usually your GitHub org/user name.
  projectName: 'NovaNo1r-Blog', // Usually your repo name.

  // Even if you don't use internalization, you can use this field to set useful
  // metadata like html lang. For example, if your site is Chinese, you may want
  // to replace "en" with "zh-Hans".
  i18n: {
    defaultLocale: 'zh-Hans',
    locales: ['zh-Hans', 'en'],
  },

  customFields: {
    // Gitalk
    gitalkClientID: process.env.GITALK_CLIENT_ID,
    gitalkSecret: process.env.GITALK_CLIENT_SECRET,
    gitalkREPO: process.env.GITALK_REPO,
    gitalkOwner: process.env.GITALK_OWNER,
    gitalkAdmin: process.env.GITALK_ADMIN

  },

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        pages: {
          path: 'src/contents/pages'
        },
        docs: false,
        sitemap: {
          changefreq: 'weekly',
          priority: 0.5,
          ignorePatterns: ['/tags/**'],
          filename: 'sitemap.xml',
        },
        blog: false,
        theme: {
          customCss: [
            require.resolve('./src/theme/css/custom.scss')
          ],
        },
      }),
    ],
  ],

  plugins: [
    [
      '@docusaurus/plugin-content-docs',
      {
        id: 'default',
        path: 'src/contents/library',
        routeBasePath: 'library',
        editUrl:
        'https://github.com/MuelNova/Muel-Nova-Blog/tree/main/',
      }
    ],
    [
      '@docusaurus/plugin-content-blog',
      {
        id: 'reproducing',
        routeBasePath: 'reproducing',
        path: 'src/contents/reproducing',
        feedOptions: {
          type: 'rss',
          copyright: `Copyright © ${new Date().getFullYear()} NovaNo1r with ❤`,
        },
        authorsMapPath: "../blog/authors.yml"
      },
    ],

    [
      '@docusaurus/plugin-content-blog',
      {
        id: "default",
        path: 'src/contents/blog',
        blogTitle: 'BLOG',
        blogSidebarTitle: 'Written with 😢tears and loves❤',
        blogSidebarCount: 'ALL',
        showReadingTime: true,
        // Please change this to your repo.
        // Remove this to remove the "edit this page" links.
        editUrl:
          'https://github.com/MuelNova/NovaNo1r-Blog/tree/main/',
        feedOptions: {
          type: 'rss',
          copyright: `Copyright © ${new Date().getFullYear()} NovaNo1r with ❤`,
        },
      }
    ],
    
    [
      '@docusaurus/plugin-content-blog',
      {
        id: "posts",
        path: 'src/contents/posts',
        routeBasePath: 'posts',
        // sidebarPath: require.resolve('./sidebars.js'),
        // Please change this to your repo.
        // Remove this to remove the "edit this page" links.
        authorsMapPath: "../blog/authors.yml",
        editUrl:
          'https://github.com/MuelNova/NovaNo1r-Blog/tree/main/',
          
        
        feedOptions: {
          type: 'rss',
          copyright: `Copyright © ${new Date().getFullYear()} NovaNo1r with ❤`,
        },
      }
    ],
    'docusaurus-plugin-sass',
    'plugin-image-zoom',
    [
      '@docusaurus/plugin-google-gtag',
      {
        trackingID: process.env.GTAG,
        anonymizeIP: true,
      },
    ],
  ],

  themes: [
    // ... Your other themes.
    [
      require.resolve("@easyops-cn/docusaurus-search-local"),
      {
        // ... Your options.
        // `hashed` is recommended as long-term-cache of index file is possible.
        hashed: true,
        indexBlog: true,
        docsRouteBasePath: ["blockchain", "pwn"],
        language: ["en", "zh"],
        
        // For Docs using Chinese, The `language` is recommended to set to:
        // ```
        // language: ["en", "zh"],
        // ```
      },
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    {
      giscus: {
        repo: process.env.GISCUS_REPO,
        repoId: process.env.GISCUS_REPO_ID,
        category: process.env.GISCUS_CATEGORY,
        categoryId: process.env.GISCUS_CATEGORY_ID,
        lightCss: process.env.GISCUS_LIGHT_CSS,
        darkCss: process.env.GISCUS_DARK_CSS
      },
      navbar: {
        title: 'Muel-Nova',
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
          {to: '/library', label: '♿️Library', position: 'left'},
          {
            href: 'https://github.com/MuelNova',
            label: 'GitHub',
            position: 'right',
          },
          // To-Do: About Page Nav
          // {
          //   type: 'html',
          //   value: '<a class="menu__link"></a>'
          // },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Here',
            items: [
              {to: '/blog', label: '📝Blog'},
              {to: '/library', label: '♿️Library'},
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
                href: 'https://github.com/MuelNova',
              }
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} <a href="/about">MuelNova</a>. Built with <a href="https://docusaurus.io/">Docusaurus</a> filling with ❤ and 🥛`,
      },
      prism: {
        theme: lightCodeTheme,
        darkTheme: darkCodeTheme,
        additionalLanguages: ['powershell', 'bash']
      },
      tableOfContents: {
        minHeadingLevel: 2,
        maxHeadingLevel: 5,
      },
      imageZoom: {
        // CSS selector to apply the plugin to, defaults to '.markdown img'
        selector: '.markdown img',
        // Optional medium-zoom options
        // see: https://www.npmjs.com/package/medium-zoom#options
        options: {
          margin: 24,
          background: '#222222',
          // scrollOffset: 40,
          // container: '#zoom-container',
          // template: '#zoom-template',
        },
      },
      // announcementBar: {
        // id: 'Warning',
        // content:
        //   '网站正在重写前端，你可能会遇到一些问题阻止你的正常访问！',
        // backgroundColor: '#fafbfc',
        // textColor: '#091E42',
        // isCloseable: true,
      // },
    },
};

module.exports = config;
