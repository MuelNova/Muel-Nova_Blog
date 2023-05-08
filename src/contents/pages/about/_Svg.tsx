import React from 'react';

interface SvgProps {
    Svg: React.FunctionComponent<React.SVGProps<SVGElement>>;
    link: string;
    Name?: string;
    style?: React.CSSProperties;
}

const Svg: React.FC<SvgProps> = ({ Svg, link, Name='', style={}}) => {
    return (
      <a href={link} target='_blank'>
        <Svg className={Name} style={style}/>
      </a>
    )
}



export default Svg;