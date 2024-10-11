import Follow from "@site/src/static/img/follow.svg";
import { faQq } from "@fortawesome/free-brands-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import React from "react";


const svgList = [
  {
    title: "QQ(4050909)",
    Svg: ({ ...props }) => <FontAwesomeIcon icon={faQq} {...props}/>,
    link: "https://qm.qq.com/q/2liGTvjIM",
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
