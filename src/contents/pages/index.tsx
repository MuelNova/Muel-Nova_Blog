import React from 'react';
import { useState } from 'react';
import styles from '@site/src/contents/pages/index.module.scss';
import Link from '@docusaurus/Link';

import TitleImg from '@site/src/static/img/index/menu/title.svg';
import StarIcon from '@site/src/static/img/index/menu/star.svg';
import MoonIcon from '@site/src/static/img/index/menu/moon.svg';
import DogIcon from '@site/src/static/img/index/menu/dog.svg';
import MountainIcon from '@site/src/static/img/index/menu/mountain.svg';
import ProfileImg from '@site/src/static/img/index/menu/menu-1.svg';
import SiteImg from '@site/src/static/img/index/menu/menu-2.svg';
import ProductImg from '@site/src/static/img/index/menu/menu-3.svg';
import MemoriesImg from '@site/src/static/img/index/menu/menu-4.svg';
import svgList from '@site/src/theme/utils/_SocialMediaList'

const Svg = ({ Svg, link }) => {
  return (
    <a href={link} target='_blank'>
      <Svg className={styles['last-chapter__sns-nav']} />
    </a>
  )
}


function AboutComponent() {
  const [dropMenu, setDropMenu] = useState(false);
  return (
      <article className={styles['last-chapter']}>
      <div className={styles['last-chapter__bg-help']} />
      <div className={styles['last-chapter__bg']} />
      <div className={styles['last-chapter__ball']} />
      <div className={styles['last-chapter__frame']}>
        <div />
        <div />
        <div />
        <div />
      </div>
      <div className={styles['last-chapter__decoration']}>
        <div className={styles['star']} />
        <div className={styles['star']} />
        <div className={styles['star']} />
        <div className={styles['star']} />
        <div className={styles['moon']} />
      </div>
      <div className={styles['last-chapter__logo']} />
      <nav className={styles['last-chapter__sns-nav']}>
        { svgList.map((item, _) => {
          return <Svg {...item} key={item.title}/>
        })}
      </nav>

      <button type="button"
              className={styles['last-chapter__menu-btn']}
              aria-expanded={dropMenu ? "true" : "false"}
              onClick={() => setDropMenu((prev) => !prev)}>
        <div />
        <div />
        <div />
      </button>
      <DropMenu dropMenu={dropMenu} setDropMenu={setDropMenu}/>
    </article>    
  );
}


const DropMenu = ({dropMenu, setDropMenu}) => (
  <div className={`${styles['menu']} ${dropMenu ? styles['show'] : ""}`}>
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
            <p className={styles["text"]}>博客</p>
            {/* <SiteImg className={styles["title"]} /> */}
          </div>
        </Link>
        <Link to="/posts">
          <div className={styles["inner"]}>
            <div className={styles["icon"]}>
              <MoonIcon />
            </div>
            <p className={styles["text"]}>文章</p>
            {/* <MemoriesImg className={styles["title"]} /> */}
          </div>
        </Link>
        <Link to="/reproducing">
          <div className={styles["inner"]}>
            <div className={styles["icon"]}>
              <DogIcon />
            </div>
            <p className={styles["text"]}>复现</p>
            {/* <ProductImg className={styles["title"]} /> */}
          </div>
        </Link>
        <Link to="/about">
          <div className={styles["inner"]}>
            <div className={styles["icon"]}>
              <StarIcon />
            </div>
            <p className={styles["text"]}>关于</p>
            {/* <ProfileImg className={styles["title"]} /> */}
          </div>
        </Link>
      </nav>
      <div className={styles["colors"]}>
        <div></div><div></div><div></div><div></div>
      </div>
    </section>
    <button type="button"
            className={styles["menu__close-btn"]}
            aria-expanded={dropMenu ? "true" : "false"}
            onClick={() => setDropMenu((prev) => !prev)}>
      <div></div><div></div>
    </button>
  </div>
)


export default function Home(): JSX.Element {
    return (
        <main>
          <AboutComponent />
        </main>
    );
  }
