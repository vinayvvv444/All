﻿//using Microsoft.AspNetCore.Authorization;
//using Microsoft.OpenApi.Models;
//using Swashbuckle.AspNetCore.SwaggerGen;

//namespace All.Filters
//{
//    public class AuthorizeCheckOperationFilter : IOperationFilter
//    {
//        public void Apply(OpenApiOperation operation, OperationFilterContext context)
//        {
//            var authAttributes = context.MethodInfo.DeclaringType
//                .GetCustomAttributes(true)
//                .Union(context.MethodInfo.GetCustomAttributes(true))
//                .OfType<AuthorizeAttribute>();

//            if (authAttributes.Any())
//            {
//                operation.Security = new List<OpenApiSecurityRequirement>
//            {
//                new OpenApiSecurityRequirement
//                {
//                    {
//                        new OpenApiSecurityScheme
//                        {
//                            Reference = new OpenApiReference
//                            {
//                                Type = ReferenceType.SecurityScheme,
//                                Id = "Bearer"
//                            }
//                        },
//                        new List<string>()
//                    }
//                }
//            };
//            }
//        }
//    }
//}

