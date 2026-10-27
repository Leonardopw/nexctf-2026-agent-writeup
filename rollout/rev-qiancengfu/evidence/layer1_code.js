
var RUNES = "PWd4UGRoUlEwWURLTW96UGRoUlEwWWpOQVFWS2VKZ0RBd3lI";
var SPIRIT_KEY = "QiXuanMen";

/* 与掌柜同款的封印手法：符胆 -> 逐字节异或灵钥(循环) -> base64 -> 整体反转 -> 再 base64 */
function wrapTicket(plain) {
    var mixed = "";
    for (var i = 0; i < plain.length; i++) {
        mixed += String.fromCharCode(plain.charCodeAt(i) ^ SPIRIT_KEY.charCodeAt(i % SPIRIT_KEY.length));
    }
    var layer1 = btoa(mixed);
    var layer2 = layer1.split("").reverse().join("");
    return btoa(layer2);
}

function check() {
    var outEl = document.getElementById("out");
    var v = document.getElementById("in").value.trim();
    try {
        if (wrapTicket(v) === RUNES) {
            outEl.textContent = "对上了！掌柜娘子冲你笑了笑：『拆封印的手艺不错，符胆归你了。』";
            outEl.className = "ok";
        } else {
            outEl.textContent = "对不上。三层封印，你真的全揭开了吗？";
            outEl.className = "bad";
        }
    } catch (e) {
        outEl.textContent = "符纸微微发烫，似乎没听懂你写的东西。";
        outEl.className = "bad";
    }
}

document.getElementById("chant").textContent = RUNES;
document.getElementById("go").addEventListener("click", check);
