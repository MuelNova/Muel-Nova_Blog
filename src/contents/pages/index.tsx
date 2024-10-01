import React, { useEffect } from "react";
import { useState } from "react";
import styles from "@site/src/contents/pages/index.module.scss";
import Link from "@docusaurus/Link";
import Translate from "@docusaurus/Translate";

import TitleImg from "@site/src/static/img/index/menu/title.svg";
import StarIcon from "@site/src/static/img/index/menu/star.svg";
import MoonIcon from "@site/src/static/img/index/menu/moon.svg";
import DogIcon from "@site/src/static/img/index/menu/dog.svg";
import MountainIcon from "@site/src/static/img/index/menu/mountain.svg";
import AniEnabledIcon from "@site/src/static/img/index/menu/ani_enable.svg";
import AniDisabledIcon from "@site/src/static/img/index/menu/ani_disable.svg";
import svgList from "@site/src/theme/utils/_SocialMediaList";
import Svg from "@site/src/contents/pages/about/_Svg";

function AboutComponent() {
  const [dropMenu, setDropMenu] = useState(false);
  const [hasPlayedAnimation, setHasPlayedAnimation] = useState(false);
  const [disableAnimation, setDisableAnimation] = useState(false);

  useEffect(() => {
    const savedDisableAnimation =
      localStorage.getItem("disableAnimation") === "true";
    setDisableAnimation(savedDisableAnimation);

    const showFirstAnimation = !sessionStorage.getItem("hasPlayedAnimation");

    if (!savedDisableAnimation && showFirstAnimation) {
      setHasPlayedAnimation(false);
      sessionStorage.setItem("hasPlayedAnimation", "true");
    } else {
      setHasPlayedAnimation(true);
    }
  }, []);

  const DropMenu = () => (
    <div className={`${styles["menu"]} ${dropMenu ? styles["show"] : ""}`}>
      <section className={styles["menu__space"]}>
        <div />
        <div />
        <div />
        <div />
      </section>
      <section className={styles["menu__box"]}>
        <div className={styles["bg"]} />
        <TitleImg className={styles["menu-title"]} />
        <nav className={styles["nav"]}>
          <Link to="/blog">
            <div className={styles["inner"]}>
              <div className={styles["icon"]}>
                <MountainIcon />
              </div>
              <p className={styles["text"]}>
                <Translate>博客</Translate>
              </p>
              {/* <SiteImg className={styles["title"]} /> */}
            </div>
          </Link>
          <Link to="/posts">
            <div className={styles["inner"]}>
              <div className={styles["icon"]}>
                <MoonIcon />
              </div>
              <p className={styles["text"]}>
                <Translate>文章</Translate>
              </p>
              {/* <MemoriesImg className={styles["title"]} /> */}
            </div>
          </Link>
          <Link to="/reproducing">
            <div className={styles["inner"]}>
              <div className={styles["icon"]}>
                <DogIcon />
              </div>
              <p className={styles["text"]}>
                <Translate>复现</Translate>
              </p>
              {/* <ProductImg className={styles["title"]} /> */}
            </div>
          </Link>
          <Link to="/about">
            <div className={styles["inner"]}>
              <div className={styles["icon"]}>
                <StarIcon />
              </div>
              <p className={styles["text"]}>
                <Translate>关于</Translate>
              </p>
              {/* <ProfileImg className={styles["title"]} /> */}
            </div>
          </Link>
          <Link to="/links">
            <div className={styles["inner"]}>
              <div className={styles["icon"]}>
                <MountainIcon />
              </div>
              <p className={styles["text"]}>
                <Translate>友链</Translate>
              </p>
              {/* <ProfileImg className={styles["title"]} /> */}
            </div>
          </Link>
        </nav>
        <div className={styles["colors"]}>
          <div></div>
          <div></div>
          <div></div>
          <div></div>
        </div>
      </section>
      <button
        type="button"
        className={styles["menu__close-btn"]}
        aria-expanded={dropMenu ? "true" : "false"}
        onClick={() => {
          setDropMenu((prev) => !prev);
          if (!hasPlayedAnimation) {
            setHasPlayedAnimation(true);
          }
        }}
      >
        <div></div>
        <div></div>
      </button>
    </div>
  );

  return (
    <article
      className={`${styles["last-chapter"]} ${
        hasPlayedAnimation ? styles["animation-done"] : styles["animation"]
      }`}
    >
      <div className={styles["last-chapter__bg-help"]} />
      <div className={styles["last-chapter__bg"]} />
      <div className={styles["last-chapter__ball"]} />
      <div className={styles["last-chapter__frame"]}>
        <div />
        <div />
        <div />
        <div />
      </div>
      <div className={styles["last-chapter__decoration"]}>
        <div className={styles["star"]} />
        <div className={styles["star"]} />
        <div className={styles["star"]} />
        <div className={styles["star"]} />
        <div className={styles["moon"]} />
      </div>
      <div className={styles["last-chapter__logo"]} />
      <nav className={styles["last-chapter__sns-nav"]}>
        {svgList.map((item, _) => {
          return <Svg {...item} key={item.title} />;
        })}
      </nav>

      <button
        className={styles["anibtn"]}
        onClick={() => {
          const prev = disableAnimation;
          setDisableAnimation(!prev);
          setHasPlayedAnimation(!prev);
          localStorage.setItem("disableAnimation", (!prev).toString());
        }}
      >
        {!disableAnimation ? <AniEnabledIcon /> : <AniDisabledIcon />}
      </button>

      <button
        type="button"
        className={styles["last-chapter__menu-btn"]}
        aria-expanded={dropMenu ? "true" : "false"}
        onClick={() => {
          setDropMenu((prev) => !prev);
        }}
      >
        <div />
        <div />
        <div />
      </button>
      <DropMenu />
    </article>
  );
}

export default function Home(): JSX.Element {
  return (
    <main>
      <AboutComponent />
    </main>
  );
}
