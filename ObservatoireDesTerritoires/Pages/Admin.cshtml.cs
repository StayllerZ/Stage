using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

namespace ObservatoireDesTerritoires.Pages
{
    public class AdminModel : PageModel
    {
        public void OnGet()
        {
            string verifEncodedJwt = HttpContext.Request.Cookies["AuthToken"];

            if (string.IsNullOrEmpty(verifEncodedJwt))
            {
                throw new Exception("Jeton manquant");
            }

            // Configuration de la cl� de validation
            var validationKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("ma-super-cl�-secr�te"));

            // Configuration des param�tres de validation de jeton
            var validationParameters = new TokenValidationParameters
            {
                IssuerSigningKey = validationKey,
                ValidAudience = "Observatoire",
                ValidIssuer = "Observatoire",
                ValidateLifetime = true
            };

            SecurityToken validatedToken;

            try
            {
                // Validation du jeton
                var jwtHandler = new JwtSecurityTokenHandler();
                jwtHandler.ValidateToken(verifEncodedJwt, validationParameters, out validatedToken);
            }
            catch (SecurityTokenExpiredException)
            {
                // Jeton expir�
                throw new Exception("Jeton expir�");
            }
            catch (SecurityTokenInvalidSignatureException)
            {
                // Signature du jeton invalide
                throw new Exception("Jeton non valide");
            }

            // Acc�s aux claims
            var jwt = (JwtSecurityToken)validatedToken;
            foreach (var claim in jwt.Claims)
            {
                Console.WriteLine(claim.Type + ": " + claim.Value);
            }
        }
    }
}
