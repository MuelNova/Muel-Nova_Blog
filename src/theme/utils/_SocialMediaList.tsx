import Follow from "@site/src/static/img/follow.svg";

const svgList = [
  {
    title: "bilibili",
    Svg: require("@site/src/static/img/bilibili.svg").default,
    link: "https://space.bilibili.com/11966801",
  },
  {
    title: "github",
    Svg: require("@site/src/static/img/github.svg").default,
    link: "https://github.com/MuelNova",
  },
  {
    title: "steam",
    Svg: require("@site/src/static/img/steam.svg").default,
    link: "https://steamcommunity.com/id/muelnova",
  },
  {
    title: "Email",
    Svg: require("@site/src/static/img/email.svg").default,
    link: "mailto:muel@nova.gal",
  },
  {
    title: "Follow",
    Svg: Follow,
    link: "https://app.follow.is/profile/56300998939738112",
  },
  {
    title: "rss",
    Svg: require("@site/src/static/img/rss.svg").default,
    link: "https://nova.gal/blog/rss.xml",
  },
];

export default svgList;
