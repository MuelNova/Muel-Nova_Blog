import React from "react";

interface SvgProps {
  Svg: React.FunctionComponent<React.SVGProps<SVGElement>>;
  link: string;
  Name?: string;
  style?: React.CSSProperties;
}

const Svg: React.FC<SvgProps> = ({ Svg, link, Name = "", style = {} }) => {
  const defaultStyle: React.CSSProperties = {
    top: "20%",
    left: "20%",
    width: "60%",
    height: "60%",
    position: "absolute",
    display: "block",
  };

  style = { ...defaultStyle, ...style };

  return (
    <a href={link} target="_blank">
      <Svg className={Name} style={style} />
    </a>
  );
};

export default Svg;
