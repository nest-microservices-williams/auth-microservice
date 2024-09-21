import {
  IsEmail,
  IsString,
  IsStrongPassword,
  Matches,
  MaxLength,
  MinLength,
} from 'class-validator';

export class RegisterUserDto {
  @IsString()
  @MinLength(2)
  @MaxLength(50)
  @Matches(/^[a-zA-Z\s]+$/, {
    message: 'Name must contain only letters and spaces',
  })
  name: string;

  @IsString()
  @IsEmail()
  email: string;

  @IsString()
  @IsStrongPassword()
  password: string;
}
