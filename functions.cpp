/*
https://github.com/bhassani/EternalBlueC/blob/2bbf166a650b5ddab9e728794f65ebdc2d6eedcb/EternalBlue%20All%20in%20one/utils/ex_string.c
*/

int replace_str(char *pStrBuf, char *pOld, char *pNew);

static int _str_replace(char *p_result, char* p_source, char* p_seach, char *p_repstr)
{
    int c = 0;
    int repstr_leng = 0;
    int searchstr_leng = 0;
    char *p1;
    char *presult = p_result;
    char *psource = p_source;
    char *prep = p_repstr;
    char *pseach = p_seach;
    int nLen = 0;
    repstr_leng = strlen(prep);
    searchstr_leng = strlen(pseach);

    do
    {
        p1 = strstr(psource, p_seach);
        if (p1 == 0)
        {
            strcpy(presult, psource);
            return c;
        }
        c++;  //匹配子串计数加1;
        //printf("结果:%s\r\n", p_result);
        //printf("源字符:%s\r\n", p_source);
        // 拷贝上一个替换点和下一个替换点中间的字符串
        nLen = p1 - psource;
        memcpy(presult, psource, nLen);
        // 拷贝需要替换的字符串
        memcpy(presult + nLen, p_repstr, repstr_leng);
        psource = p1 + searchstr_leng;
        presult = presult + nLen + repstr_leng;
    }
    while (p1);

    return c;
}

//used to replace the treeid and userid placeholders in the EternalBlue code found in Wannacry
//Sample: replace_str(EternalBluePacket1,"__TREEID__PLACEHOLDER__", treeid_from_packet)
int replace_str(char *pStrBuf, char *pOld, char *pNew)
{
    int newLen = 0;
    char *pTmpBuf = NULL;

    newLen = strlen(pStrBuf) + 1000;
    pTmpBuf = (char *)malloc(newLen);
    if(pTmpBuf == NULL)
        return -1;
    memset(pTmpBuf, 0x00, newLen);

    if(_str_replace(pTmpBuf, pStrBuf, pOld, pNew) <= 0)
    {
        free(pTmpBuf);
        return -2;
    }
    memset(pStrBuf, 0x00, strlen(pStrBuf));
    strcat(pStrBuf, pTmpBuf);
    free(pTmpBuf);

    return 0;
}

