//Made by JP

export class OpenLight {
  //Cookie used for user preference does not work with local files

  constructor(changeType = "auto") {
    //Dark and light mode strings for easy readability
    this.dark = "dark";
    this.light = "light";

    this.transitionTime = "0.5s";

    this.changeTypes = { AUTO: 0, MANUAL: 1 };
    this.changeType = this.changeTypes.AUTO;

    if (changeType == "auto") {
      this.changeType = this.changeTypes.AUTO;
    } else if (changeType == "manual") {
      this.changeType = this.changeTypes.MANUAL;
    } else {
      console.error(
        'Change type not set correctly. Please use "auto" or "manual". Defaulting to auto'
      );
    }

    this.version = "1.2"; //Current running version

    this.overridedClasses = [];

    this.mode = this.dark; //default mode is light mode (it is toggles when the window loads)
    this.openlightcookie; //cookie to store prefered mode

    //Foreground and background mode ids
    this.modeBackgroundId = "lightDarkB";
    this.modeForegroundId = "lightDarkF";

    //Corresponding colors for forground and background of light mode and dark mode (these are just default colors)
    this.openLightColors = {
      darkBackgroundStyle: "rgb(30, 30, 38)",
      lightBackgroundStyle: "rgb(255, 255, 255)",
      darkForegroundStyle: "rgb(240, 240, 250)",
      lightForegroundStyle: "rgb(30, 30, 40)",
    };

    //Background and foreground HTML elements
    this.backgrounds = [];

    this.foregrounds = [];
  }

  //Add tags that should be used in auto mode
  addBackgroundTag(tag) {
    var elems = document.getElementsByTagName(tag);

    if (this.changeType == this.changeTypes.MANUAL) {
      console.error("Sorry, you cannot add tags in manual mode");
      return;
    }

    if (this.backgrounds.includes(elems)) {
      return;
    } else {
      this.foregrounds.push(document.getElementsByTagName(tag));
    }
  }

  //Add tags that should be used in auto mode
  addForegroundTag(tag) {
    var elems = document.getElementsByTagName(tag);

    if (this.changeType == this.changeTypes.MANUAL) {
      console.error("Sorry, you cannot add tags in manual mode");
      return;
    }

    if (this.foregrounds.includes(elems)) {
      return;
    } else {
      this.foregrounds.push(document.getElementsByTagName(tag));
    }
  }

  addOverrideByClassName(className) {
    this.overridedClasses.push(className);
  }

  //Check if HTML element has a className which is overrided
  arrayCompare(x, y, array) {
    for (var i = 0; i < this.overridedClasses.length; i++) {
      if (array[x][y].classList.contains(this.overridedClasses[i])) {
        return false; //Is in the the overrided classes
      }
    }
    return true; //Is not in the overrided classes
  }

  //Use manual dark mode
  toggleModeManual() {
    if (this.mode == this.dark) {
      this.mode = this.light;
      this.lightModeManual();
    } else {
      this.mode = this.dark;
      this.darkModeManual();
    }
  }

  //Manually change the page to light mode
  lightModeManual() {
    var backgroundElem = document.getElementsByClassName(this.modeBackgroundId);
    var foregroundElem = document.getElementsByClassName(this.modeForegroundId);

    //Loops through all the elments with the background class name
    for (var i = 0; i < backgroundElem.length; i++) {
      //Checks set default
      if (backgroundElem[i].classList.contains(this.light)) {
        backgroundElem[i].style.backgroundColor =
          this.openLightColors.lightBackgroundStyle;
      } else {
        backgroundElem[i].style.backgroundColor =
          this.openLightColors.darkBackgroundStyle;
      }
    }

    //Loops through all the elments with the foreground class name
    for (var i = 0; i < foregroundElem.length; i++) {
      //Checks set default
      if (foregroundElem[i].classList.contains(this.light)) {
        foregroundElem[i].style.color =
          this.openLightColors.lightForegroundStyle;
      } else {
        foregroundElem[i].style.color =
          this.openLightColors.darkForegroundStyle;
      }
    }
    //toggleButton.className="fas fa-moon";
  }

  //Manually change the page to dark mode
  darkModeManual() {
    var backgroundElem = document.getElementsByClassName(this.modeBackgroundId);
    var foregroundElem = document.getElementsByClassName(this.modeForegroundId);

    //Loops through all the elments with the background class name
    for (var i = 0; i < backgroundElem.length; i++) {
      //Checks set default
      if (backgroundElem[i].classList.contains(this.light)) {
        backgroundElem[i].style.backgroundColor =
          this.openLightColors.darkBackgroundStyle;
      } else {
        backgroundElem[i].style.backgroundColor =
          this.openLightColors.lightBackgroundStyle;
      }
    }

    //Loops through all the elments with the foreground class name
    for (var i = 0; i < foregroundElem.length; i++) {
      //Checks set default
      if (foregroundElem[i].classList.contains(this.light)) {
        foregroundElem[i].style.color =
          this.openLightColors.darkForegroundStyle;
      } else {
        foregroundElem[i].style.color =
          this.openLightColors.lightForegroundStyle;
      }
    }
  }

  init() {
    //Set cookie variable
    this.openlightcookie = this.getCookie("openlightcookie");
    //If the cookie is no empty
    if (this.openlightcookie != "") {
      console.log("Cookie is set");
      this.mode = this.openlightcookie; //Set the mode to the user's prefered mode
    } else {
      console.log("Cookie is not set");
    }

    if (this.changeType == this.changeTypes.MANUAL) {
      //Add smooth transition when changing
      var elements = document.getElementsByClassName(this.modeBackgroundId);

      for (var i = 0; i < elements.length; i++) {
        elements[i].style.transitionDuration = this.transitionTime;
      }

      for (var i = 0; i < elements.length; i++) {
        elements[i].style.transitionDuration = this.transitionTime;
      }

      //Set the initial mode
      if (this.mode == this.dark) {
        this.darkModeManual();
      } else {
        this.lightModeManual();
      }
    } else if (this.changeType == this.changeTypes.AUTO) {
      this.initAuto();
      if (this.mode == this.dark) {
        this.darkModeAuto();
      } else {
        this.lightModeAuto();
      }
    }

    console.log("OpenLight initialized with mode " + this.changeType + "!");
    console.log(
      "This site uses OpenLight version " +
        this.version +
        " for dark mode toggling!"
    );
  }

  initAuto() {
    //Set the HTML element variables
    this.backgrounds = [
      document.getElementsByTagName("button"),
      document.getElementsByTagName("input"),
      document.getElementsByTagName("div"),
      document.getElementsByTagName("nav"),
      document.getElementsByTagName("body"),
      document.getElementsByTagName("ul"),
      document.getElementsByTagName("ol"),
    ];

    this.foregrounds = [
      document.getElementsByTagName("button"),
      document.getElementsByTagName("input"),
      document.getElementsByTagName("label"),
      document.getElementsByTagName("li"),
      document.getElementsByTagName("td"),
      document.getElementsByTagName("th"),
      document.getElementsByTagName("div"),
      document.getElementsByTagName("body"),
      document.getElementsByTagName("q"),
      document.getElementsByTagName("b"),
      document.getElementsByTagName("p"),
      document.getElementsByTagName("h1"),
      document.getElementsByTagName("h2"),
      document.getElementsByTagName("h3"),
      document.getElementsByTagName("h4"),
      document.getElementsByTagName("h5"),
      document.getElementsByTagName("h6"),
    ];

    //Get rid of elements that don't exist in array
    for (var i = 0; i < this.backgrounds.length; i++) {
      if (this.backgrounds[i].length == 0) {
        this.backgrounds.splice(i, 1);
        i--;
      }
    }

    for (var i = 0; i < this.foregrounds.length; i++) {
      if (this.foregrounds[i].length == 0) {
        this.foregrounds.splice(i, 1);
        i--;
      }
    }

    //Set default colors for light mode
    for (var i = 0; i < this.backgrounds.length; i++) {
      for (var j = 0; j < this.backgrounds[i].length; j++) {
        if (this.arrayCompare(i, j, this.backgrounds)) {
          this.backgrounds[i][j].style.backgroundColor =
            this.openLightColors.lightBackgroundStyle; //Change  color
          this.backgrounds[i][j].style.transitionDuration = this.transitionTime; //Add smooth transition
        }
      }
    }

    for (var i = 0; i < this.foregrounds.length; i++) {
      for (var j = 0; j < this.foregrounds[i].length; j++) {
        if (this.arrayCompare(i, j, this.foregrounds)) {
          this.foregrounds[i][j].style.color =
            this.openLightColors.lightForegroundStyle; //Change color
          this.foregrounds[i][j].style.transitionDuration = this.transitionTime; //Add smooth transition
        }
      }
    }
  }

  //Automatically change the page to dark mode
  darkModeAuto() {
    for (var i = 0; i < this.backgrounds.length; i++) {
      for (var j = 0; j < this.backgrounds[i].length; j++) {
        if (this.arrayCompare(i, j, this.backgrounds)) {
          this.backgrounds[i][j].style.backgroundColor =
            this.openLightColors.darkBackgroundStyle;
        }
      }
    }

    for (var i = 0; i < this.foregrounds.length; i++) {
      for (var j = 0; j < this.foregrounds[i].length; j++) {
        if (this.arrayCompare(i, j, this.foregrounds)) {
          this.foregrounds[i][j].style.color =
            this.openLightColors.darkForegroundStyle;
        }
      }
    }
  }

  //Automatically change the page to light mode
  lightModeAuto() {
    for (var i = 0; i < this.backgrounds.length; i++) {
      for (var j = 0; j < this.backgrounds[i].length; j++) {
        if (this.arrayCompare(i, j, this.backgrounds)) {
          this.backgrounds[i][j].style.backgroundColor =
            this.openLightColors.lightBackgroundStyle;
        }
      }
    }

    for (var i = 0; i < this.foregrounds.length; i++) {
      for (var j = 0; j < this.foregrounds[i].length; j++) {
        if (this.arrayCompare(i, j, this.foregrounds)) {
          this.foregrounds[i][j].style.color =
            this.openLightColors.lightForegroundStyle;
        }
      }
    }
  }

  //Use automatic dark mode
  toggleModeAuto() {
    if (this.mode == this.dark) {
      this.mode = this.light;
      this.lightModeAuto();
    } else {
      this.mode = this.dark;
      this.darkModeAuto();
    }
  }

  //Toggle between dark and light mode
  toggleMode() {
    if (this.changeType == this.changeTypes.MANUAL) {
      this.toggleModeManual();
    } else if (this.changeType == this.changeTypes.AUTO) {
      this.toggleModeAuto();
    }

    this.setCookie("openlightcookie", this.mode, 30);
  }

  //Change to light mode
  lightMode() {
    this.mode = this.light;

    if (this.changeType == this.changeTypes.MANUAL) {
      this.lightModeManual();
    } else if (this.changeType == this.changeTypes.AUTO) {
      this.lightModeAuto();
    }
  }

  //Change to dark mode
  darkMode() {
    this.mode = this.dark;

    if (this.changeType == this.changeTypes.MANUAL) {
      this.darkModeManual();
    } else if (this.changeType == this.changeTypes.AUTO) {
      this.darkModeAuto();
    }
  }

  //changeType to auto
  auto() {
    this.changeType = this.changeTypes.AUTO;
  }

  //changeType to manual
  manual() {
    this.changeType = this.changeTypes.MANUAL;
  }

  //Used to set openlightcookie (function from w3schools)
  setCookie(cname, cvalue, exdays) {
    var d = new Date();
    d.setTime(d.getTime() + exdays * 24 * 60 * 60 * 1000);
    var expires = "expires=" + d.toUTCString();
    document.cookie = cname + "=" + cvalue + ";" + expires + ";path=/";
  }

  //Used to get openlightcookie (function from w3schools)
  getCookie(cname) {
    var name = cname + "=";
    var decodedCookie = decodeURIComponent(document.cookie);
    var ca = decodedCookie.split(";");
    for (var i = 0; i < ca.length; i++) {
      var c = ca[i];
      while (c.charAt(0) == " ") {
        c = c.substring(1);
      }
      if (c.indexOf(name) == 0) {
        return c.substring(name.length, c.length);
      }
    }
    return "";
  }
}
