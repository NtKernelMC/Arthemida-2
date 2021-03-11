/*************************************************
*     libucp - Unicode Property Table handler    *
*************************************************/

/* These are the character categories that are returned by ucp_findchar */

typedef enum
{
  ucp_C,     /* Other */
  ucp_L,     /* Letter */
  ucp_M,     /* Mark */
  ucp_N,     /* Number */
  ucp_P,     /* Punctuation */
  ucp_S,     /* Symbol */
  ucp_Z      /* Separator */
} ucp1;

/* These are the detailed character types that are returned by ucp_findchar */

typedef enum
{
  ucp_Cc,    /* Control */
  ucp_Cf,    /* Format */
  ucp_Cn,    /* Unassigned */
  ucp_Co,    /* Private use */
  ucp_Cs,    /* Surrogate */
  ucp_Ll,    /* Lower case letter */
  ucp_Lm,    /* Modifier letter */
  ucp_Lo,    /* Other letter */
  ucp_Lt,    /* Title case letter */
  ucp_Lu,    /* Upper case letter */
  ucp_Mc,    /* Spacing mark */
  ucp_Me,    /* Enclosing mark */
  ucp_Mn,    /* Non-spacing mark */
  ucp_Nd,    /* Decimal number */
  ucp_Nl,    /* Letter number */
  ucp_No,    /* Other number */
  ucp_Pc,    /* Connector punctuation */
  ucp_Pd,    /* Dash punctuation */
  ucp_Pe,    /* Close punctuation */
  ucp_Pf,    /* Final punctuation */
  ucp_Pi,    /* Initial punctuation */
  ucp_Po,    /* Other punctuation */
  ucp_Ps,    /* Open punctuation */
  ucp_Sc,    /* Currency symbol */
  ucp_Sk,    /* Modifier symbol */
  ucp_Sm,    /* Mathematical symbol */
  ucp_So,    /* Other symbol */
  ucp_Zl,    /* Line separator */
  ucp_Zp,    /* Paragraph separator */
  ucp_Zs     /* Space separator */
} ucp2;
typedef struct
{
    const char* name;
    int         value;
} ucp_type_table;

static ucp_type_table utt[] = {{"C", 128 + ucp_C}, {"Cc", ucp_Cc}, {"Cf", ucp_Cf},     {"Cn", ucp_Cn}, {"Co", ucp_Co}, {"Cs", ucp_Cs},     {"L", 128 + ucp_L},
                               {"Ll", ucp_Ll},     {"Lm", ucp_Lm}, {"Lo", ucp_Lo},     {"Lt", ucp_Lt}, {"Lu", ucp_Lu}, {"M", 128 + ucp_M}, {"Mc", ucp_Mc},
                               {"Me", ucp_Me},     {"Mn", ucp_Mn}, {"N", 128 + ucp_N}, {"Nd", ucp_Nd}, {"Nl", ucp_Nl}, {"No", ucp_No},     {"P", 128 + ucp_P},
                               {"Pc", ucp_Pc},     {"Pd", ucp_Pd}, {"Pe", ucp_Pe},     {"Pf", ucp_Pf}, {"Pi", ucp_Pi}, {"Po", ucp_Po},     {"Ps", ucp_Ps},
                               {"S", 128 + ucp_S}, {"Sc", ucp_Sc}, {"Sk", ucp_Sk},     {"Sm", ucp_Sm}, {"So", ucp_So}, {"Z", 128 + ucp_Z}, {"Zl", ucp_Zl},
                               {"Zp", ucp_Zp},     {"Zs", ucp_Zs}};
/* For use in PCRE we make this function static so that there is no conflict if
PCRE is linked with an application that makes use of an external version -
assuming an external version is ever released... */

static int ucp_findchar(const int, int*, int*);
/* End of ucp.h */
