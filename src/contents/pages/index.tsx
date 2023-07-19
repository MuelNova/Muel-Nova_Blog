import React from 'react';
import { useState } from 'react';
import styles from './index.module.scss';
import Link from '@docusaurus/Link';

import TitleImg from '@site/static/img/index/menu/title.svg';
import StarIcon from '@site/static/img/index/menu/star.svg';
import MoonIcon from '@site/static/img/index/menu/moon.svg';
import DogIcon from '@site/static/img/index/menu/dog.svg';
import MountainIcon from '@site/static/img/index/menu/mountain.svg';
import ProfileImg from '@site/static/img/index/menu/menu-1.svg';
import SiteImg from '@site/static/img/index/menu/menu-2.svg';
import ProductImg from '@site/static/img/index/menu/menu-3.svg';
import MemoriesImg from '@site/static/img/index/menu/menu-4.svg';

const Svg = ({ Svg, link }) => {
  return (
    <a href={link} target='_blank'>
      <Svg className={styles['last-chapter__sns-nav']} />
    </a>
  )
}
const svgList = [
  {
    title: 'bilibili',
    Svg: require('@site/static/img/bilibili.svg').default,
    link: 'https://space.bilibili.com/11966801'
  },
  {
    title: 'github',
    Svg: require('@site/static/img/github.svg').default,
    link: 'https://github.com/MuelNova'
  }
]



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
            <SiteImg className={styles["title"]} />
          </div>
        </Link>
        <Link to="/posts">
          <div className={styles["inner"]}>
            <div className={styles["icon"]}>
              <MountainIcon />
            </div>
            <MemoriesImg className={styles["title"]} />
          </div>
        </Link>
        <Link to="/about">
          <div className={styles["inner"]}>
            <div className={styles["icon"]}>
              <StarIcon />
            </div>
            <ProfileImg className={styles["title"]} />
          </div>
        </Link>
        <Link to="/reproducing">
          <div className={styles["inner"]}>
            <div className={styles["icon"]}>
              <DogIcon />
            </div>
            <ProductImg className={styles["title"]} />
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
